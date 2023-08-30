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

package signer

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/getamis/sirius/log"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	signer "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/sign"
	"github.com/getamis/alice/example/cggmp/reshare"
	"github.com/getamis/alice/example/cggmp/utils"
	"github.com/getamis/alice/example/node"
)

type SignerConfig struct {
	node.PeerConfig       `yaml:",omitempty,inline"`
	reshare.ReshareResult `yaml:",omitempty,inline"`

	Threshold uint32 `yaml:"threshold"`
	SessionId string `yaml:"sessionId"`
	Message   string `yaml:"msg"`
}

type SignerResult struct {
	R string `yaml:"r"`
	S string `yaml:"s"`
}

const signerProtocol = "/signer/1.0.0"

var Cmd = &cobra.Command{
	Use:  "signer",
	Long: `Signing for using the secret shares to generate a signature.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		yamlFile, err := os.ReadFile(viper.GetString("config"))
		if err != nil {
			return err
		}

		cfg := SignerConfig{}
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
		pm := node.NewPeerManager(selfId, host, signerProtocol)

		for _, p := range cfg.Peers {
			pm.AddPeer(p.Id, node.GetPeerAddr(p.Port, p.Id))
		}

		l := node.NewListener()

		dkgResult, err := utils.ConvertDKGResult(cfg.Pubkey, cfg.Share, cfg.BKs, cfg.Rid)
		if err != nil {
			log.Warn("Cannot get DKG result", "err", err)
			return err
		}

		// Signer needs results from DKG and reshare.
		reshareResult, err := utils.ConvertReshareResult(cfg.Share, cfg.PaillierKey, cfg.YSecret, cfg.PartialPublicKeys, cfg.Y, cfg.PedParameters)
		if err != nil {
			log.Warn("Cannot get DKG result", "err", err)
			return err
		}

		ssid := cggmp.ComputeSSID([]byte(cfg.SessionId), []byte(dkgResult.Bks[selfId].String()), dkgResult.Rid)

		// Create signer
		signerCore, err := signer.NewSign(
			cfg.Threshold,
			ssid,
			reshareResult.Share,
			dkgResult.PublicKey,
			reshareResult.PartialPubKey,
			reshareResult.PaillierKey,
			reshareResult.PedParameter,
			dkgResult.Bks,
			[]byte(cfg.Message),
			pm,
			l,
		)
		if err != nil {
			log.Warn("Cannot create a new signer", "err", err)
			return err
		}

		// Create a new node.
		node := node.New[*signer.Message, *signer.Result](signerCore, l, pm)
		if err != nil {
			log.Crit("Failed to new service", "err", err)
		}

		// Set a stream handler on the host.
		host.SetStreamHandler(signerProtocol, func(s network.Stream) {
			node.Handle(s)
		})

		// Ensure all peers are connected before starting signing process.
		pm.EnsureAllConnected()

		// Start the signing process.
		result, err := node.Process()
		if err != nil {
			return err
		}

		signerResult := &SignerResult{
			R: result.R.String(),
			S: result.S.String(),
		}

		fmt.Println()
		rawResult, _ := yaml.Marshal(signerResult)
		fmt.Println(string(rawResult))

		return nil
	},
}
