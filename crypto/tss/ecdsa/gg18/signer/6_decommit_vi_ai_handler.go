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
	"math/big"

	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type decommitViAiData struct {
	vi *pt.ECPoint
	ai *pt.ECPoint
}

type decommitViAiHandler struct {
	*commitViAiHandler

	ui          *pt.ECPoint
	uiCommitter *commitment.HashCommitmenter
	ti          *pt.ECPoint
	tiCommitter *commitment.HashCommitmenter
}

func newDecommitViAiHandler(p *commitViAiHandler) (*decommitViAiHandler, error) {
	return &decommitViAiHandler{
		commitViAiHandler: p,
	}, nil
}

func (p *decommitViAiHandler) MessageType() types.MessageType {
	return types.MessageType(Type_DecommitViAi)
}

func (p *decommitViAiHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *decommitViAiHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.decommitViAi != nil
}

func (p *decommitViAiHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	// Verify li and rhoI
	body := msg.GetDecommitViAi()
	err := body.LiProof.Verify(p.r)
	if err != nil {
		logger.Warn("Failed to verify li proof message", "err", err)
		return err
	}
	err = body.RhoIProof.Verify(p.g)
	if err != nil {
		logger.Warn("Failed to verify rho i proof message", "err", err)
		return err
	}

	// Decommit Vi and Ai
	vi, err := commitment.GetPointFromHashCommitment(peer.commitViAi.viCommitment, body.ViDecommitment)
	if err != nil {
		logger.Warn("Failed to decommit vi message", "err", err)
		return err
	}
	ai, err := commitment.GetPointFromHashCommitment(peer.commitViAi.aiCommitment, body.AiDecommitment)
	if err != nil {
		logger.Warn("Failed to decommit ai message", "err", err)
		return err
	}

	peer.decommitViAi = &decommitViAiData{
		vi: vi,
		ai: ai,
	}
	return peer.AddMessage(msg)
}

func (p *decommitViAiHandler) Finalize(logger log.Logger) (types.Handler, error) {
	// Build V and its committer
	v, err := buildV(logger, p.publicKey, p.r.GetX(), p.vi, p.peers, new(big.Int).SetBytes(p.msg))
	if err != nil {
		return nil, err
	}
	p.ui = v.ScalarMult(p.rhoI)
	p.uiCommitter, err = commitment.NewCommitterByPoint(p.ui)
	if err != nil {
		return nil, err
	}

	// Build A and its committer
	a, err := buildA(logger, p.ai, p.peers)
	if err != nil {
		return nil, err
	}
	p.ti = a.ScalarMult(p.li)
	p.tiCommitter, err = commitment.NewCommitterByPoint(p.ti)
	if err != nil {
		return nil, err
	}

	//Build and send Type_SignerCommitUiTi message
	msg := p.getCommitUiTiMessage()
	p.broadcast(msg)
	return newCommitUiTiHandler(p)
}

func (p *decommitViAiHandler) getDecommitUiTiMessage() *Message {
	return &Message{
		Type: Type_DecommitUiTi,
		Id:   p.peerManager.SelfID(),
		Body: &Message_DecommitUiTi{
			DecommitUiTi: &BodyDecommitUiTi{
				UiDecommitment: p.uiCommitter.GetDecommitmentMessage(),
				TiDecommitment: p.tiCommitter.GetDecommitmentMessage(),
			},
		},
	}
}

func (p *decommitViAiHandler) getCommitUiTiMessage() *Message {
	return &Message{
		Type: Type_CommitUiTi,
		Id:   p.peerManager.SelfID(),
		Body: &Message_CommitUiTi{
			CommitUiTi: &BodyCommitUiTi{
				UiCommitment: p.uiCommitter.GetCommitmentMessage(),
				TiCommitment: p.tiCommitter.GetCommitmentMessage(),
			},
		},
	}
}

func buildV(logger log.Logger, pubkey *pt.ECPoint, rx *big.Int, selfVi *pt.ECPoint, peers map[string]*peer, m *big.Int) (*pt.ECPoint, error) {
	var err error
	// Calculate the sum of vi
	sumVi := selfVi
	for id, peer := range peers {
		sumVi, err = sumVi.Add(peer.decommitViAi.vi)
		if err != nil {
			logger.Warn("Failed to add vi", "id", id, "vi", peer.decommitViAi.vi, "err", err)
			return nil, err
		}
	}

	// V := -m*G +(-Rx)*Q+sum_i Vi
	negMg := pt.ScalarBaseMult(pubkey.GetCurve(), new(big.Int).Neg(m))
	negRxQ := pubkey.ScalarMult(new(big.Int).Neg(rx))
	V, err := negMg.Add(negRxQ)
	if err != nil {
		logger.Warn("Failed to get the sum of negMg and negRxQ", "err", err)
		return nil, err
	}
	V, err = V.Add(sumVi)
	if err != nil {
		logger.Warn("Failed to get the sum of V and the sum of Vi", "err", err)
		return nil, err
	}
	return V, nil
}

func buildA(logger log.Logger, selfAi *pt.ECPoint, peers map[string]*peer) (*pt.ECPoint, error) {
	var err error
	A := selfAi
	for id, peer := range peers {
		A, err = A.Add(peer.decommitViAi.ai)
		if err != nil {
			logger.Warn("Failed to add ai", "id", id, "ai", peer.decommitViAi.ai, "err", err)
			return nil, err
		}
	}
	return A, nil
}
