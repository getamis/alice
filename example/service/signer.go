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
package service

import (
	"io/ioutil"

	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/tss/signer"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/alice/example/utils"
	"github.com/getamis/sirius/log"
	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
)

var msg = []byte{1, 2, 3}

// For simplicity, we use Paillier algorithm in signer.
var homoFunc = func() (homo.Crypto, error) {
	return paillier.NewPaillier(2048)
}

type signerService struct {
	config *config.Config
	pm     types.PeerManager

	signer *signer.Signer
	done   chan struct{}
}

func NewSignerService(config *config.Config, pm types.PeerManager) (*signerService, error) {
	s := &signerService{
		config: config,
		pm:     pm,
		done:   make(chan struct{}),
	}

	// Signer needs results from DKG.
	dkgResult, err := utils.ReadDKGResult(pm.SelfID())
	if err != nil {
		log.Warn("Cannot get signer result", "err", err)
		return nil, err
	}

	h, err := homoFunc()
	if err != nil {
		log.Warn("Cannot create a homo function", "err", err)
		return nil, err
	}

	// Create signer
	signer, err := signer.NewSigner(pm, dkgResult.PublicKey, h, dkgResult.Share, dkgResult.Bks, msg, s)
	if err != nil {
		log.Warn("Cannot create a new signer", "err", err)
		return nil, err
	}
	s.signer = signer
	return s, nil
}

func (p *signerService) Handle(s network.Stream) {
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

func (p *signerService) Process() {
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

func (p *signerService) OnStateChanged(oldState types.MainState, newState types.MainState) {
	if newState == types.StateFailed {
		log.Error("Signer failed", "old", oldState.String(), "new", newState.String())
		close(p.done)
		return
	} else if newState == types.StateDone {
		log.Info("Signer done", "old", oldState.String(), "new", newState.String())
		result, err := p.signer.GetResult()
		if err == nil {
			utils.WriteSignerResult(p.pm.SelfID(), result)
		} else {
			log.Warn("Failed to get result from signer", "err", err)
		}
		close(p.done)
		return
	}
	log.Info("State changed", "old", oldState.String(), "new", newState.String())
}
