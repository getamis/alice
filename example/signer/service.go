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
	"io/ioutil"

	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/tss/signer"
	"github.com/getamis/alice/example/utils"
	"github.com/getamis/sirius/log"
	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
)

var msg = []byte{1, 2, 3}

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
	dkgResult, err := convertDKGResult(config)
	if err != nil {
		log.Warn("Cannot get signer result", "err", err)
		return nil, err
	}

	// For simplicity, we use Paillier algorithm in signer.
	paillier, err := paillier.NewPaillier(2048)
	if err != nil {
		log.Warn("Cannot create a paillier function", "err", err)
		return nil, err
	}

	// Create signer
	signer, err := signer.NewSigner(pm, dkgResult.PublicKey, paillier, dkgResult.Share, dkgResult.Bks, msg, s)
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

	// 2. Connect the host to peers and send the public key message to them.
	msg := p.signer.GetPubkeyMessage()
	for _, peerPort := range p.config.Peers {
		p.pm.MustSend(utils.GetPeerIDFromPort(peerPort), msg)
	}

	// 3. Wait the signer is done or failed
	<-p.done
}

func (p *service) OnStateChanged(oldState types.MainState, newState types.MainState) {
	if newState == types.StateFailed {
		log.Error("Signer failed", "old", oldState.String(), "new", newState.String())
		close(p.done)
		return
	} else if newState == types.StateDone {
		log.Info("Signer done", "old", oldState.String(), "new", newState.String())
		result, err := p.signer.GetResult()
		if err == nil {
			writeSignerResult(p.pm.SelfID(), result)
		} else {
			log.Warn("Failed to get result from signer", "err", err)
		}
		close(p.done)
		return
	}
	log.Info("State changed", "old", oldState.String(), "new", newState.String())
}
