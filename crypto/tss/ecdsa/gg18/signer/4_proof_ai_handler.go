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
	"math/big"

	"github.com/getamis/alice/crypto/elliptic"

	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/mta"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	// ErrIndentityR is returned if the R is an identity element
	ErrIndentityR = errors.New("identity r")
)

type proofAiData struct {
	aiG *pt.ECPoint
}

type proofAiHandler struct {
	*deltaHandler

	r              *pt.ECPoint
	li             *big.Int
	liProof        *zkproof.SchnorrProofMessage
	vi             *pt.ECPoint
	viCommitmenter *commitment.HashCommitmenter
	rhoI           *big.Int
	rhoIProof      *zkproof.SchnorrProofMessage
	ai             *pt.ECPoint
	aiCommitmenter *commitment.HashCommitmenter
	si             *big.Int
}

func newproofAiHandler(p *deltaHandler) (*proofAiHandler, error) {
	return &proofAiHandler{
		deltaHandler: p,
	}, nil
}

func (p *proofAiHandler) MessageType() types.MessageType {
	return types.MessageType(Type_ProofAi)
}

func (p *proofAiHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *proofAiHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.proofAi != nil
}

func (p *proofAiHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	body := msg.GetProofAi()

	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	// Verify ag decommit message
	agPoint, err := commitment.GetPointFromHashCommitment(peer.pubkey.aigCommit, body.GetAgDecommitment())
	if err != nil {
		return err
	}

	// Verify ag schnorr proof
	err = body.GetAiProof().Verify(p.g)
	if err != nil {
		logger.Warn("Failed to verify aig schnorr proof", "err", err)
		return err
	}

	peer.proofAi = &proofAiData{
		aiG: agPoint,
	}
	return peer.AddMessage(msg)
}

func (p *proofAiHandler) Finalize(logger log.Logger) (types.Handler, error) {
	var err error
	p.r = p.aiMta.GetAG(p.getCurve())
	for id, peer := range p.peers {
		p.r, err = p.r.Add(peer.proofAi.aiG)
		if err != nil {
			logger.Warn("Failed to add point", "id", id, "err", err)
			return nil, err
		}
	}
	p.r = p.r.ScalarMult(p.inverseDelta)
	if p.r.IsIdentity() {
		logger.Warn("R is an identity element")
		return nil, ErrIndentityR
	}

	p.si = buildSi(p.aiMta, p.getN(), p.r.GetX(), p.tmpSi, new(big.Int).SetBytes(p.msg))

	p.li, p.vi, p.liProof, p.viCommitmenter, err = buildViCommitter(logger, p.si, p.r)
	if err != nil {
		return nil, err
	}

	p.rhoI, p.ai, p.rhoIProof, p.aiCommitmenter, err = buildAiCommitter(logger, p.getCurve())
	if err != nil {
		return nil, err
	}

	//Send Type_SignerCommitViAi message
	msg := p.getCommitAiViMessage()
	p.broadcast(msg)
	return newCommitViAiHandler(p)
}

func (p *proofAiHandler) getCommitAiViMessage() *Message {
	return &Message{
		Type: Type_CommitViAi,
		Id:   p.peerManager.SelfID(),
		Body: &Message_CommitViAi{
			CommitViAi: &BodyCommitViAi{
				ViCommitment: p.viCommitmenter.GetCommitmentMessage(),
				AiCommitment: p.aiCommitmenter.GetCommitmentMessage(),
			},
		},
	}
}

func (p *proofAiHandler) getDecommitAiViMessage() *Message {
	return &Message{
		Type: Type_DecommitViAi,
		Id:   p.peerManager.SelfID(),
		Body: &Message_DecommitViAi{
			DecommitViAi: &BodyDecommitViAi{
				ViDecommitment: p.viCommitmenter.GetDecommitmentMessage(),
				AiDecommitment: p.aiCommitmenter.GetDecommitmentMessage(),
				RhoIProof:      p.rhoIProof,
				LiProof:        p.liProof,
			},
		},
	}
}

// s’_i=Rx*si+m*k_i
func buildSi(aiMta mta.Mta, n *big.Int, rx *big.Int, tmpSi *big.Int, msg *big.Int) *big.Int {
	r1 := new(big.Int).Mul(rx, tmpSi)
	r2 := aiMta.GetProductWithK(msg)
	r := new(big.Int).Add(r1, r2)
	return new(big.Int).Mod(r, n)
}

func buildViCommitter(logger log.Logger, si *big.Int, r *pt.ECPoint) (*big.Int, *pt.ECPoint, *zkproof.SchnorrProofMessage, *commitment.HashCommitmenter, error) {
	curve := r.GetCurve()
	n := curve.Params().N
	li, err := utils.RandomInt(n)
	if err != nil {
		logger.Warn("Failed to random li", "err", err)
		return nil, nil, nil, nil, err
	}
	proofLi, err := zkproof.NewSchorrMessage(si, li, r)
	if err != nil {
		logger.Warn("Failed to proof li", "err", err)
		return nil, nil, nil, nil, err
	}

	// Vi := si * R + li * G
	siR := r.ScalarMult(si)
	liG := pt.ScalarBaseMult(curve, li)
	Vi, err := siR.Add(liG)
	if err != nil {
		logger.Warn("Failed to add siR and liG", "err", err)
		return nil, nil, nil, nil, err
	}
	viCommitmenter, err := commitment.NewCommitterByPoint(Vi)
	if err != nil {
		logger.Warn("Failed to new viCommitmenter", "err", err)
		return nil, nil, nil, nil, err
	}
	return li, Vi, proofLi, viCommitmenter, nil
}

func buildAiCommitter(logger log.Logger, curve elliptic.Curve) (*big.Int, *pt.ECPoint, *zkproof.SchnorrProofMessage, *commitment.HashCommitmenter, error) {
	n := curve.Params().N
	rhoI, err := utils.RandomInt(n)
	if err != nil {
		logger.Warn("Failed to random rho i", "err", err)
		return nil, nil, nil, nil, err
	}
	proofRhoI, err := zkproof.NewBaseSchorrMessage(curve, rhoI)
	if err != nil {
		logger.Warn("Failed to proof rho i", "err", err)
		return nil, nil, nil, nil, err
	}

	Ai := pt.ScalarBaseMult(curve, rhoI)
	aiCommitmenter, err := commitment.NewCommitterByPoint(Ai)
	if err != nil {
		logger.Warn("Failed to new aiCommitmenter", "err", err)
		return nil, nil, nil, nil, err
	}
	return rhoI, Ai, proofRhoI, aiCommitmenter, nil
}
