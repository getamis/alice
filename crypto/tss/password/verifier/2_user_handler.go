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
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/sirius/log"
)

type userHandler2 struct {
	*userHandler1
}

func newUserHandler2(s *userHandler1) (*userHandler2, error) {
	return &userHandler2{
		userHandler1: s,
	}, nil
}

func (p *userHandler2) MessageType() types.MessageType {
	return types.MessageType(Type_MsgServer2)
}

func (p *userHandler2) GetRequiredMessageCount() uint32 {
	return 1
}

func (p *userHandler2) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *userHandler2) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	server2 := msg.GetServer2()
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}

	// Schnorr verify
	err := p.serverGVerifier.Verify(server2.ServerGProver3)
	if err != nil {
		logger.Debug("Failed to verify", "err", err)
		return err
	}
	osp3, err := p.shareGProver.ComputeZ(server2.ShareGVerifier2)
	if err != nil {
		logger.Debug("Failed to compute z (old share)", "err", err)
		return err
	}

	// Send to Server
	p.peerManager.MustSend(message.GetId(), &Message{
		Type: Type_MsgUser3,
		Id:   p.peerManager.SelfID(),
		Body: &Message_User3{
			User3: &BodyUser3{
				ShareGProver3: osp3,
			},
		},
	})
	return peer.AddMessage(msg)
}

func (p *userHandler2) Finalize(logger log.Logger) (types.Handler, error) {
	return nil, nil
}
