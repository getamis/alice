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
	"math/big"
	"os"

	"github.com/getamis/sirius/log"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	reshare "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	dkgexample "github.com/getamis/alice/example/cggmp/dkg"
	"github.com/getamis/alice/example/cggmp/utils"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/alice/example/node"
)

type ReshareConfig struct {
	node.PeerConfig      `yaml:",omitempty,inline"`
	dkgexample.DKGResult `yaml:",omitempty,inline"`

	Threshold uint32 `yaml:"threshold"`
	SessionId string `yaml:"sessionId"`
}

type ReshareResult struct {
	dkgexample.DKGResult `yaml:",omitempty,inline"`

	YSecret       string                                   `yaml:"ySecret"`
	PaillierKey   config.PaillierKey                       `yaml:"paillierKey"`
	Y             map[string]config.ECPoint                `yaml:"y"`
	PedParameters map[string]config.PederssenOpenParameter `yaml:"pedParameters"`
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
		defer host.Close()

		selfId := host.ID().String()

		log.Debug("my ID", "id", selfId, "addr", host.Addrs())

		// Reshare needs results from DKG.
		dkgResult, err := utils.ConvertDKGResult(cfg.Pubkey, cfg.Share, cfg.BKs, cfg.Rid)
		if err != nil {
			log.Warn("Cannot get DKG result", "err", err)
			return err
		}

		partialPublicKeys := make(map[string]*ecpointgrouplaw.ECPoint, len(cfg.PartialPublicKeys))
		for peerId, pp := range cfg.PartialPublicKeys {
			x, ok := new(big.Int).SetString(pp.X, 10)
			if !ok {
				log.Crit("Cannot convert string to big int", "x", pp.X)
			}
			y, ok := new(big.Int).SetString(pp.Y, 10)
			if !ok {
				log.Crit("Cannot convert string to big int", "y", pp.Y)
			}
			key, err := ecpointgrouplaw.NewECPoint(utils.GetCurve(), x, y)
			if err != nil {
				log.Crit("Cannot get public key", "err", err)
			}

			partialPublicKeys[peerId] = key
		}

		// Create a new peer manager.
		pm := node.NewPeerManager(selfId, host, reshareProtocol)

		for _, p := range cfg.Peers {
			pm.AddPeer(p.Id, node.GetPeerAddr(p.Port, p.Id))
		}

		l := node.NewListener()

		ssid := cggmp.ComputeSSID([]byte(cfg.SessionId), []byte(dkgResult.Bks[selfId].String()), dkgResult.Rid)

		// Create reshare core
		reshareCore, err := reshare.NewRefresh(dkgResult.Share, dkgResult.PublicKey, pm, cfg.Threshold, partialPublicKeys, dkgResult.Bks, 2048, ssid, l)
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

		log.Debug("Starting reshare process")

		// Start the reshare process.
		result, err := node.Process()
		if err != nil {
			return err
		}

		p, q := result.PaillierKey.GetPQ()

		reshareResult := &ReshareResult{
			DKGResult: dkgexample.DKGResult{
				Share:             result.Share.String(),
				PartialPublicKeys: make(map[string]config.Pubkey),
				BKs:               cfg.BKs,
				Pubkey:            cfg.Pubkey,
				Rid:               cfg.Rid,
			},
			YSecret:       result.YSecret.String(),
			PedParameters: make(map[string]config.PederssenOpenParameter),
			Y:             make(map[string]config.ECPoint),
			PaillierKey: config.PaillierKey{
				P: p.String(),
				Q: q.String(),
			},
		}

		for peerId, d := range result.PartialPubKey {
			reshareResult.PartialPublicKeys[peerId] = config.Pubkey{
				X: d.GetX().String(),
				Y: d.GetY().String(),
			}
		}

		for peerId, d := range result.PedParameter {
			reshareResult.PedParameters[peerId] = config.PederssenOpenParameter{
				N: d.GetN().String(),
				S: d.GetS().String(),
				T: d.GetT().String(),
			}
		}

		for peerId, d := range result.Y {
			reshareResult.Y[peerId] = config.ECPoint{
				X: d.GetX().String(),
				Y: d.GetY().String(),
			}
		}

		fmt.Println()
		rawResult, _ := yaml.Marshal(reshareResult)
		fmt.Println(string(rawResult))

		return nil
	},
}
