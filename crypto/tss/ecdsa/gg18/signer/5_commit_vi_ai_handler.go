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
	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type commitViAiData struct {
	viCommitment *commitment.HashCommitmentMessage
	aiCommitment *commitment.HashCommitmentMessage
}

type commitViAiHandler struct {
	*proofAiHandler
}

func newCommitViAiHandler(p *proofAiHandler) (*commitViAiHandler, error) {
	return &commitViAiHandler{
		proofAiHandler: p,
	}, nil
}

func (p *commitViAiHandler) MessageType() types.MessageType {
	return types.MessageType(Type_CommitViAi)
}

func (p *commitViAiHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *commitViAiHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.commitViAi != nil
}

func (p *commitViAiHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetCommitViAi()
	peer.commitViAi = &commitViAiData{
		viCommitment: body.ViCommitment,
		aiCommitment: body.AiCommitment,
	}
	return peer.AddMessage(msg)
}

func (p *commitViAiHandler) Finalize(logger log.Logger) (types.Handler, error) {
	msg := p.getDecommitAiViMessage()
	p.broadcast(msg)
	return newDecommitViAiHandler(p)
}
