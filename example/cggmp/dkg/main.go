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
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/getamis/sirius/log"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	"github.com/getamis/alice/example/cggmp/utils"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/alice/example/node"
)

type DKGConfig struct {
	node.PeerConfig `yaml:",omitempty,inline"`

	Rank      uint32 `yaml:"rank"`
	Threshold uint32 `yaml:"threshold"`
	SessionId string `yaml:"sessionId"`
}

type DKGResult struct {
	Share             string                   `yaml:"share"`
	Pubkey            config.Pubkey            `yaml:"pubkey"`
	BKs               map[string]config.BK     `yaml:"bks"`
	Rid               string                   `yaml:"rid"`
	PartialPublicKeys map[string]config.Pubkey `yaml:"partialPublicKeys"`
}

const (
	dkgProtocol      = "/dkg/1.0.0"
	exchangeProtocol = "/exchange-partial-publickey/1.0.0"
)

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
		dkgCore, err := dkg.NewDKG(utils.GetCurve(), pm, []byte(cfg.SessionId), cfg.Threshold, cfg.Rank, l)
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

		var (
			partialPublicKeys = map[string]*ecpointgrouplaw.ECPoint{}
			done              = make(chan struct{}, 1)
		)

		host.SetStreamHandler(exchangeProtocol, func(s network.Stream) {
			rawData, err := io.ReadAll(s)
			if err != nil {
				log.Warn("Cannot read message from peer", "err", err)
				return
			}
			s.Close()

			var msg ecpointgrouplaw.EcPointMessage

			err = proto.Unmarshal(rawData, &msg)
			if err != nil {
				log.Warn("Cannot unmarshal proto message", "err", err)
				return
			}

			p, err := msg.ToPoint()
			if err != nil {
				log.Warn("Cannot convert to EcPoint", "err", err)
				return
			}

			peerId := s.Conn().RemotePeer()

			partialPublicKeys[peerId.String()] = p

			log.Debug("Received partial public key", "peer", peerId, "point", p.String())

			if len(partialPublicKeys) == int(pm.NumPeers()+1) {
				done <- struct{}{}
			}
		})

		// Ensure all peers are connected before starting DKG process.
		pm.EnsureAllConnected()

		// Start DKG process.
		result, err := node.Process()
		if err != nil {
			return err
		}

		myPartialPublicKey := ecpointgrouplaw.ScalarBaseMult(utils.GetCurve(), result.Share)
		partialPublicKeys[selfId] = myPartialPublicKey

		log.Debug("waitForPartialPublicKeys")

		err = waitForPartialPublicKeys(selfId, host, cfg, myPartialPublicKey, done)
		if err != nil {
			return err
		}

		dkgResult := &DKGResult{
			Share: result.Share.String(),
			Pubkey: config.Pubkey{
				X: result.PublicKey.GetX().String(),
				Y: result.PublicKey.GetY().String(),
			},
			BKs:               make(map[string]config.BK),
			Rid:               hex.EncodeToString(result.Rid),
			PartialPublicKeys: make(map[string]config.Pubkey),
		}
		for peerId, bk := range result.Bks {
			dkgResult.BKs[peerId] = config.BK{
				X:    bk.GetX().String(),
				Rank: bk.GetRank(),
			}
		}

		for peerId, partialPublicKey := range partialPublicKeys {
			dkgResult.PartialPublicKeys[peerId] = config.Pubkey{
				X: partialPublicKey.GetX().String(),
				Y: partialPublicKey.GetY().String(),
			}
		}

		fmt.Println()
		rawResult, _ := yaml.Marshal(dkgResult)
		fmt.Println(string(rawResult))

		var sigs = make(chan os.Signal, 1)
		defer close(sigs)

		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigs)

		for sig := range sigs {
			log.Info("received signal", "sig", sig)
		}

		return nil
	},
}

func waitForPartialPublicKeys(selfId string, host host.Host, cfg DKGConfig, myKey *ecpointgrouplaw.ECPoint, done <-chan struct{}) error {
	// Create a new peer manager.
	pm := node.NewPeerManager(selfId, host, exchangeProtocol)

	for _, p := range cfg.Peers {
		pm.AddPeer(p.Id, node.GetPeerAddr(p.Port, p.Id))
	}

	pm.EnsureAllConnected()

	msg, err := myKey.ToEcPointMessage()
	if err != nil {
		log.Warn("Cannot convert partial public key to proto.Message", "err", err)
		return err
	}

	for _, p := range pm.PeerIDs() {
		pm.MustSend(p, msg)
	}

	<-done

	return nil
}
