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
	"errors"

	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	ErrInconsistentUT = errors.New("inconsistent U and T")
)

type decommitUiTiData struct {
	ui *pt.ECPoint
	ti *pt.ECPoint
}

type decommitUiTiHandler struct {
	*commitUiTiHandler
}

func newDecommitUiTiHandler(p *commitUiTiHandler) (*decommitUiTiHandler, error) {
	return &decommitUiTiHandler{
		commitUiTiHandler: p,
	}, nil
}

func (p *decommitUiTiHandler) MessageType() types.MessageType {
	return types.MessageType(Type_DecommitUiTi)
}

func (p *decommitUiTiHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *decommitUiTiHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.decommitUiTi != nil
}

func (p *decommitUiTiHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetDecommitUiTi()
	ui, err := commitment.GetPointFromHashCommitment(peer.commitUiTi.uiCommitment, body.UiDecommitment)
	if err != nil {
		logger.Warn("Failed to decommit ui message", "err", err)
		return err
	}
	ti, err := commitment.GetPointFromHashCommitment(peer.commitUiTi.tiCommitment, body.TiDecommitment)
	if err != nil {
		logger.Warn("Failed to decommit ti message", "err", err)
		return err
	}

	peer.decommitUiTi = &decommitUiTiData{
		ui: ui,
		ti: ti,
	}
	return peer.AddMessage(msg)
}

func (p *decommitUiTiHandler) Finalize(logger log.Logger) (types.Handler, error) {
	U, err := buildU(logger, p.ui, p.peers)
	if err != nil {
		return nil, err
	}
	T, err := buildT(logger, p.ti, p.peers)
	if err != nil {
		return nil, err
	}
	if !U.Equal(T) {
		logger.Warn("Inconsistent U and T", "ui", p.ui, "U", U, "ti", p.ti, "T", T)
		return nil, ErrInconsistentUT
	}

	// Send out the si message
	msg := p.getSiMessage()
	p.broadcast(msg)
	return newSiHandler(p)
}

func (p *decommitUiTiHandler) getSiMessage() *Message {
	return &Message{
		Type: Type_Si,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Si{
			Si: &BodySi{
				Si: p.si.Bytes(),
			},
		},
	}
}

func buildU(logger log.Logger, selfUi *pt.ECPoint, peers map[string]*peer) (*pt.ECPoint, error) {
	var err error
	U := selfUi
	for id, peer := range peers {
		U, err = U.Add(peer.decommitUiTi.ui)
		if err != nil {
			logger.Warn("Failed to add ui", "id", id, "ui", peer.decommitUiTi.ui, "err", err)
			return nil, err
		}
	}
	return U, nil
}

func buildT(logger log.Logger, selfTi *pt.ECPoint, peers map[string]*peer) (*pt.ECPoint, error) {
	var err error
	T := selfTi
	for id, peer := range peers {
		T, err = T.Add(peer.decommitUiTi.ti)
		if err != nil {
			logger.Warn("Failed to add ti", "id", id, "ti", peer.decommitUiTi.ti, "err", err)
			return nil, err
		}
	}
	return T, nil
}
