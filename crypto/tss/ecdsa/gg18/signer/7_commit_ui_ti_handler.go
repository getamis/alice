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

type commitUiTiData struct {
	uiCommitment *commitment.HashCommitmentMessage
	tiCommitment *commitment.HashCommitmentMessage
}

type commitUiTiHandler struct {
	*decommitViAiHandler
}

func newCommitUiTiHandler(p *decommitViAiHandler) (*commitUiTiHandler, error) {
	return &commitUiTiHandler{
		decommitViAiHandler: p,
	}, nil
}

func (p *commitUiTiHandler) MessageType() types.MessageType {
	return types.MessageType(Type_CommitUiTi)
}

func (p *commitUiTiHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *commitUiTiHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.commitUiTi != nil
}

func (p *commitUiTiHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetCommitUiTi()
	peer.commitUiTi = &commitUiTiData{
		uiCommitment: body.UiCommitment,
		tiCommitment: body.TiCommitment,
	}
	return peer.AddMessage(msg)
}

func (p *commitUiTiHandler) Finalize(logger log.Logger) (types.Handler, error) {
	msg := p.getDecommitUiTiMessage()
	p.broadcast(msg)
	return newDecommitUiTiHandler(p)
}
