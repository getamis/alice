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
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type serverHandler1 struct {
	*serverHandler0
	shareGVerifier *zkproof.InteractiveSchnorrVerifier
}

func newServerHandler1(s *serverHandler0) (*serverHandler1, error) {
	return &serverHandler1{
		serverHandler0: s,
	}, nil
}

func (p *serverHandler1) MessageType() types.MessageType {
	return types.MessageType(Type_MsgUser1)
}

func (p *serverHandler1) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *serverHandler1) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	user1 := msg.GetUser1()
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}

	err := p.serverGProver.SetCommitC(user1.ServerGVerifier1)
	if err != nil {
		logger.Debug("Failed to set commit c", "err", err)
		return err
	}

	p.shareGVerifier, err = zkproof.NewInteractiveSchnorrVerifier(user1.ShareGProver1)
	if err != nil {
		logger.Debug("Failed to create old share verifier", "err", err)
		return err
	}
	oldShareG := p.shareGVerifier.GetV()

	// Ensure the public key consistent
	self := p.peers[p.peerManager.SelfID()]
	err = validatePubKey(self.bkCoefficient, ecpointgrouplaw.ScalarBaseMult(p.curve, p.secret), peer.bkCoefficient, oldShareG, p.publicKey)
	if err != nil {
		return tss.ErrUnexpectedPublickey
	}

	// Send to User
	sp2, err := p.serverGProver.GetInteractiveSchnorrProver2Message()
	if err != nil {
		logger.Debug("Failed to get interactive prover 2", "err", err)
		return err
	}

	p.peerManager.MustSend(message.GetId(), &Message{
		Type: Type_MsgServer1,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Server1{
			Server1: &BodyServer1{
				ShareGVerifier1: p.shareGVerifier.GetInteractiveSchnorrVerifier1Message(),
				ServerGProver2:  sp2,
			},
		},
	})
	return peer.AddMessage(msg)
}

func (p *serverHandler1) Finalize(logger log.Logger) (types.Handler, error) {
	return newServerHandler2(p)
}
