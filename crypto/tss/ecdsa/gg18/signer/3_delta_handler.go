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

	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type deltaData struct {
	delta *big.Int
}

type deltaHandler struct {
	*mtaHandler

	inverseDelta *big.Int
}

func newDeltaHandler(p *mtaHandler) (*deltaHandler, error) {
	return &deltaHandler{
		mtaHandler: p,
	}, nil
}

func (p *deltaHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Delta)
}

func (p *deltaHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *deltaHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.delta != nil
}

func (p *deltaHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	body := msg.GetDelta()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	peer.delta = &deltaData{
		delta: new(big.Int).SetBytes(body.GetDelta()),
	}
	return peer.AddMessage(msg)
}

func (p *deltaHandler) Finalize(logger log.Logger) (types.Handler, error) {
	delta := new(big.Int).Set(p.deltaI)
	for _, peer := range p.peers {
		delta = new(big.Int).Add(delta, peer.delta.delta)
	}
	p.inverseDelta = new(big.Int).ModInverse(delta, p.getN())

	// Build and send out delta message
	msg, err := p.getProofAiMessage()
	if err != nil {
		logger.Warn("Failed to get proof ai message", "err", err)
		return nil, err
	}
	p.broadcast(msg)
	return newproofAiHandler(p)
}

func (p *mtaHandler) getProofAiMessage() (*Message, error) {
	aProofMsg, err := p.aiMta.GetAProof(p.getCurve())
	if err != nil {
		return nil, err
	}
	return &Message{
		Type: Type_ProofAi,
		Id:   p.peerManager.SelfID(),
		Body: &Message_ProofAi{
			ProofAi: &BodyProofAi{
				AgDecommitment: p.agCommitmenter.GetDecommitmentMessage(),
				AiProof:        aProofMsg,
			},
		},
	}, nil
}
