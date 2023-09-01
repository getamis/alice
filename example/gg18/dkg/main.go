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

package dkg

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

	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/alice/example/gg18/utils"
	"github.com/getamis/alice/example/node"
)

type DKGConfig struct {
	node.PeerConfig `yaml:",omitempty,inline"`

	Rank      uint32 `yaml:"rank"`
	Threshold uint32 `yaml:"threshold"`
}

type DKGResult struct {
	Share  string               `yaml:"share"`
	Pubkey config.Pubkey        `yaml:"pubkey"`
	BKs    map[string]config.BK `yaml:"bks"`
}

const dkgProtocol = "/dkg/1.0.0"

var Cmd = &cobra.Command{
	Use:  "dkg",
	Long: `Distributed key generation for creating secret shares without any dealer.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		yamlFile, err := os.ReadFile(viper.GetString("config"))
		if err != nil {
			return err
		}

		cfg := DKGConfig{}
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
		pm := node.NewPeerManager(selfId, host, dkgProtocol)

		for _, p := range cfg.Peers {
			pm.AddPeer(p.Id, node.GetPeerAddr(p.Port, p.Id))
		}

		l := node.NewListener()

		// Create dkg
		dkgCore, err := dkg.NewDKG(utils.GetCurve(), pm, cfg.Threshold, cfg.Rank, l)
		if err != nil {
			log.Warn("Cannot create a new DKG", "config", cfg, "err", err)
			return err
		}

		// Create a new service.
		node := node.New[*dkg.Message, *dkg.Result](dkgCore, l, pm)
		if err != nil {
			log.Crit("Failed to new service", "err", err)
		}

		// Set a stream handler on the host.
		host.SetStreamHandler(dkgProtocol, func(s network.Stream) {
			node.Handle(s)
		})

		// Ensure all peers are connected before starting DKG process.
		pm.EnsureAllConnected()

		// Start DKG process.
		result, err := node.Process()
		if err != nil {
			return err
		}

		dkgResult := &DKGResult{
			Share: result.Share.String(),
			Pubkey: config.Pubkey{
				X: result.PublicKey.GetX().String(),
				Y: result.PublicKey.GetY().String(),
			},
			BKs: make(map[string]config.BK),
		}
		for peerID, bk := range result.Bks {
			dkgResult.BKs[peerID] = config.BK{
				X:    bk.GetX().String(),
				Rank: bk.GetRank(),
			}
		}

		fmt.Println()
		rawResult, _ := yaml.Marshal(dkgResult)
		fmt.Println(string(rawResult))

		return nil
	},
}
