// Copyright © 2020 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package signer

import (
	"encoding/hex"
	"github.com/decred/dcrd/dcrec/edwards"
	"io/ioutil"
	"math/big"

	"crypto/ed25519"
	"github.com/getamis/alice/crypto/tss/eddsa/frost/signer"
	"github.com/getamis/alice/example/utils"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
)

type service struct {
	config *SignerConfig
	pm     types.PeerManager

	signer *signer.Signer
	done   chan struct{}
}

func NewService(config *SignerConfig, pm types.PeerManager) (*service, error) {
	s := &service{
		config: config,
		pm:     pm,
		done:   make(chan struct{}),
	}

	// Signer needs results from DKG.
	dkgResult, err := utils.ConvertDKGResult(config.Pubkey, config.Share, config.BKs)
	if err != nil {
		log.Warn("Cannot get DKG result", "err", err)
		return nil, err
	}

	// For simplicity, we use Paillier algorithm in signer.

	// Create signer
	signer, err := signer.NewSigner(dkgResult.PublicKey, pm, (uint32)(len(dkgResult.Bks)), dkgResult.Share, dkgResult.Bks, []byte(config.Message), s)
	if err != nil {
		log.Warn("Cannot create a new signer", "err", err)
		return nil, err
	}
	s.signer = signer
	return s, nil
}

func (p *service) Handle(s network.Stream) {
	data := &signer.Message{}
	buf, err := ioutil.ReadAll(s)
	if err != nil {
		log.Warn("Cannot read data from stream", "err", err)
		return
	}
	s.Close()

	// unmarshal it
	err = proto.Unmarshal(buf, data)
	if err != nil {
		log.Error("Cannot unmarshal data", "err", err)
		return
	}

	log.Info("Received request", "from", s.Conn().RemotePeer())
	err = p.signer.AddMessage(data)
	if err != nil {
		log.Warn("Cannot add message to signer", "err", err)
		return
	}
}

func (p *service) Process() {
	// 1. Start a signer process.
	p.signer.Start()
	defer p.signer.Stop()

	// 2. Wait the signer is done or failed
	<-p.done
}

func (p *service) OnStateChanged(oldState types.MainState, newState types.MainState) {
	if newState == types.StateFailed {
		log.Error("Signer failed", "old", oldState.String(), "new", newState.String())
		close(p.done)
		return
	} else if newState == types.StateDone {
		sigBytes := new([]byte)
		log.Info("Signer done", "old", oldState.String(), "new", newState.String())
		result, err := p.signer.GetResult()
		if err == nil {
			writeEDSignerResult(p.pm.SelfID()+"-ed25519", result, sigBytes)
			// Build public key.
			x, ok := new(big.Int).SetString(p.config.Pubkey.X, 10)
			if !ok {
				log.Error("Cannot convert string to big int", "x", p.config.Pubkey.X)
				return
			}
			y, ok := new(big.Int).SetString(p.config.Pubkey.Y, 10)
			if !ok {
				log.Error("Cannot convert string to big int", "y", p.config.Pubkey.Y)
				return
			}
			pubkey := edwards.NewPublicKey(edwards.Edwards(), x, y)
			ret := ed25519.Verify(pubkey.Serialize(), []byte(p.config.Message), *sigBytes)
			log.Info("verify ", "result", ret, "sigBytes", hex.EncodeToString(*sigBytes), "\n", "\n")
		} else {
			log.Warn("Failed to get result from signer", "err", err)
		}
		close(p.done)
		return
	}
	log.Info("State changed", "old", oldState.String(), "new", newState.String())
}
