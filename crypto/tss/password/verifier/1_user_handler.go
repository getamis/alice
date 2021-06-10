// Copyright © 2021 AMIS Technologies
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

package verifier

import (
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type userHandler1 struct {
	*userHandler0
}

func newUserHandler1(s *userHandler0) (*userHandler1, error) {
	return &userHandler1{
		userHandler0: s,
	}, nil
}

func (p *userHandler1) MessageType() types.MessageType {
	return types.MessageType(Type_MsgServer1)
}

func (p *userHandler1) GetRequiredMessageCount() uint32 {
	return 1
}

func (p *userHandler1) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *userHandler1) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	server1 := msg.GetServer1()
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}

	// Ensure public key consistent
	sG := p.serverGVerifier.GetV()
	self := p.peers[p.peerManager.SelfID()]
	err := validatePubKey(logger, peer.bkCoefficient, sG, self.bkCoefficient, ecpointgrouplaw.ScalarBaseMult(p.curve, p.share), p.publicKey)
	if err != nil {
		return tss.ErrUnexpectedPublickey
	}

	// Schnorr verify
	err = p.serverGVerifier.SetB(server1.GetServerGProver2())
	if err != nil {
		logger.Debug("Failed to set b (server G)", "err", err)
		return err
	}
	err = p.shareGProver.SetCommitC(server1.GetShareGVerifier1())
	if err != nil {
		logger.Debug("Failed to set commit c (old share)", "err", err)
		return err
	}

	// Send to Server
	osp2, err := p.shareGProver.GetInteractiveSchnorrProver2Message()
	if err != nil {
		logger.Debug("Failed to get prover message 2 (old share)", "err", err)
		return err
	}

	p.peerManager.MustSend(message.GetId(), &Message{
		Type: Type_MsgUser2,
		Id:   p.peerManager.SelfID(),
		Body: &Message_User2{
			User2: &BodyUser2{
				ShareGProver2:    osp2,
				ServerGVerifier2: p.serverGVerifier.GetInteractiveSchnorrVerifier2Message(),
			},
		},
	})
	return peer.AddMessage(msg)
}

func (p *userHandler1) Finalize(logger log.Logger) (types.Handler, error) {
	return newUserHandler2(p)
}
