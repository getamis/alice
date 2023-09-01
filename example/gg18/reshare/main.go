// Copyright © 2023 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reshare

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/getamis/sirius/log"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/reshare"
	"github.com/getamis/alice/example/gg18/dkg"
	"github.com/getamis/alice/example/gg18/utils"
	"github.com/getamis/alice/example/node"
)

type ReshareConfig struct {
	node.PeerConfig `yaml:",omitempty,inline"`
	dkg.DKGResult   `yaml:",omitempty,inline"`

	Threshold uint32 `yaml:"threshold"`
}

type ReshareResult struct {
	Share string `yaml:"share"`
}

const reshareProtocol = "/reshare/1.0.0"

var Cmd = &cobra.Command{
	Use:  "reshare",
	Long: `Refresh the secret shares without changing the public key.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		yamlFile, err := os.ReadFile(viper.GetString("config"))
		if err != nil {
			return err
		}

		cfg := ReshareConfig{}
		err = yaml.Unmarshal(yamlFile, &cfg)
		if err != nil {
			return err
		}

		rawIdentity, err := base64.StdEncoding.DecodeString(cfg.Identity)
		priv, err := crypto.UnmarshalPrivateKey(rawIdentity)
		if err != nil {
			log.Crit("Failed to unmarshal", "err", err)
		}

		// Make a host that listens on the given multiaddress.
		host, err := node.MakeBasicHost(cfg.Port, priv)
		if err != nil {
			log.Crit("Failed to create a basic host", "err", err)
		}

		selfId := host.ID().String()

		log.Debug("my ID", "id", selfId, "addr", host.Addrs())

		// Create a new peer manager.
		pm := node.NewPeerManager(selfId, host, reshareProtocol)

		for _, p := range cfg.Peers {
			pm.AddPeer(p.Id, node.GetPeerAddr(p.Port, p.Id))
		}

		// Reshare needs results from DKG.
		dkgResult, err := utils.ConvertDKGResult(cfg.Pubkey, cfg.Share, cfg.BKs)
		if err != nil {
			log.Warn("Cannot get DKG result", "err", err)
			return err
		}

		l := node.NewListener()

		// Create reshare core
		reshareCore, err := reshare.NewReshare(pm, cfg.Threshold, dkgResult.PublicKey, dkgResult.Share, dkgResult.Bks, l)
		if err != nil {
			log.Warn("Cannot create a new reshare core", "err", err)
			return err
		}

		// Create a new node.
		node := node.New[*reshare.Message, *reshare.Result](reshareCore, l, pm)
		if err != nil {
			log.Crit("Failed to new service", "err", err)
		}

		// Set a stream handler on the host.
		host.SetStreamHandler(reshareProtocol, func(s network.Stream) {
			node.Handle(s)
		})

		// Ensure all peers are connected before starting reshare process.
		pm.EnsureAllConnected()

		// Start the reshare process.
		result, err := node.Process()
		if err != nil {
			return err
		}

		reshareResult := &ReshareResult{
			Share: result.Share.String(),
		}

		rawResult, _ := yaml.Marshal(reshareResult)
		fmt.Println(string(rawResult))

		return nil
	},
}
