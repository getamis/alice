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
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type serverHandler2 struct {
	*serverHandler1
}

func newServerHandler2(s *serverHandler1) (*serverHandler2, error) {
	return &serverHandler2{
		serverHandler1: s,
	}, nil
}

func (p *serverHandler2) MessageType() types.MessageType {
	return types.MessageType(Type_MsgUser2)
}

func (p *serverHandler2) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *serverHandler2) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	user2 := msg.GetUser2()
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}

	// Schnorr verify
	err := p.shareGVerifier.SetB(user2.ShareGProver2)
	if err != nil {
		logger.Debug("Failed to set B (old share)", "err", err)
		return err
	}

	sp3, err := p.serverGProver.ComputeZ(user2.ServerGVerifier2)
	if err != nil {
		logger.Debug("Failed to compute z", "err", err)
		return err
	}

	// Send to User
	p.peerManager.MustSend(message.GetId(), &Message{
		Type: Type_MsgServer2,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Server2{
			Server2: &BodyServer2{
				ShareGVerifier2: p.shareGVerifier.GetInteractiveSchnorrVerifier2Message(),
				ServerGProver3:  sp3,
			},
		},
	})
	return peer.AddMessage(msg)
}

func (p *serverHandler2) Finalize(logger log.Logger) (types.Handler, error) {
	return newServerHandler3(p)
}

func (p *serverHandler2) GetFirstMessage() *Message {
	return nil
}
