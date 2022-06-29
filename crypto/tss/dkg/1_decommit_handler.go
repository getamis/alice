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

package dkg

import (
	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type decommitData struct {
	u0g           *ecpointgrouplaw.ECPoint
	verifyMessage *Message
}

type decommitHandler struct {
	*peerHandler
}

func newDecommitHandler(p *peerHandler) *decommitHandler {
	return &decommitHandler{
		peerHandler: p,
	}
}

func (p *decommitHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Decommit)
}

func (p *decommitHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *decommitHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.decommit != nil
}

func (p *decommitHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	// Ensure decommit successfully
	body := msg.GetDecommit()
	peerMessage := getMessageByType(peer, Type_Peer)
	u0g, err := commitment.GetPointFromHashCommitment(peerMessage.GetPeer().GetCommitment(), body.GetHashDecommitment())
	if err != nil {
		logger.Warn("Failed to get u0g", "err", err)
		return err
	}

	// Build and send the verify message
	v := p.feldmanCommitmenter.GetVerifyMessage(peer.peer.bk)
	peer.decommit = &decommitData{
		u0g: u0g,
		verifyMessage: &Message{
			Type: Type_Verify,
			Id:   p.peerManager.SelfID(),
			Body: &Message_Verify{
				Verify: &BodyVerify{
					Verify: v,
				},
			},
		},
	}
	p.peerManager.MustSend(id, peer.decommit.verifyMessage)
	return peer.AddMessage(msg)
}

func (p *decommitHandler) Finalize(logger log.Logger) (types.Handler, error) {
	return newVerifyHandler(p), nil
}
