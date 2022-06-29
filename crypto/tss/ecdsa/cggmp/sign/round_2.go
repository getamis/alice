// Copyright © 2022 AMIS Technologies
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

package sign

import (
	"errors"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	// ErrZeroR is returned if the r is zero
	ErrZeroR = errors.New("zero r")
)

type round2Data struct {
	allGammaPoint *pt.ECPoint
	psiProof      *paillierzkproof.PaillierAffAndGroupRangeMessage
	psihatProoof  *paillierzkproof.PaillierAffAndGroupRangeMessage
	d             *big.Int
	f             *big.Int
	dhat          *big.Int
	fhat          *big.Int
	alpha         *big.Int
	alphahat      *big.Int
}

type round2Handler struct {
	*round1Handler
}

func newRound2Handler(round1Handler *round1Handler) (*round2Handler, error) {
	return &round2Handler{
		round1Handler: round1Handler,
	}, nil
}

func (p *round2Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round2)
}

func (p *round2Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round2Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round2Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}
	round2 := msg.GetRound2()
	Gamma, err := round2.Gamma.ToPoint()
	if err != nil {
		logger.Debug("Failed to Gamma.ToPoint", "err", err)
		return err
	}

	ownPed := p.own.para
	n := peer.para.Getn()
	// Verify psi
	err = round2.Psi.Verify(parameter, peer.ssidWithBk, p.paillierKey.GetN(), n, p.kCiphertext, new(big.Int).SetBytes(round2.D), new(big.Int).SetBytes(round2.F), ownPed, Gamma)
	if err != nil {
		logger.Debug("Failed to verify", "err", err)
		return err
	}
	// Verify phiHat
	bkPartialKey := peer.partialPubKey.ScalarMult(peer.bkcoefficient)
	err = round2.Psihat.Verify(parameter, peer.ssidWithBk, p.paillierKey.GetN(), n, p.kCiphertext, new(big.Int).SetBytes(round2.Dhat), new(big.Int).SetBytes(round2.Fhat), ownPed, bkPartialKey)
	if err != nil {
		logger.Debug("Failed to verify", "err", err)
		return err
	}
	// Verify phipai
	curve := p.pubKey.GetCurve()
	G := pt.NewBase(curve)
	err = round2.Psipai.Verify(parameter, peer.ssidWithBk, peer.round1Data.gammaCiphertext, n, ownPed, Gamma, G)
	if err != nil {
		logger.Debug("Failed to verify", "err", err)
		return err
	}
	alpha, err := p.paillierKey.Decrypt(round2.D)
	if err != nil {
		logger.Debug("Failed to decrypt", "err", err)
		return err
	}
	alphahat, err := p.paillierKey.Decrypt(round2.Dhat)
	if err != nil {
		logger.Debug("Failed to decrypt", "err", err)
		return err
	}

	peer.round2Data = &round2Data{
		psiProof:      round2.Psi,
		d:             new(big.Int).SetBytes(round2.D),
		f:             new(big.Int).SetBytes(round2.F),
		psihatProoof:  round2.Psihat,
		dhat:          new(big.Int).SetBytes(round2.Dhat),
		fhat:          new(big.Int).SetBytes(round2.Fhat),
		alpha:         new(big.Int).SetBytes(alpha),
		alphahat:      new(big.Int).SetBytes(alphahat),
		allGammaPoint: Gamma,
	}
	return peer.AddMessage(msg)
}

func (p *round2Handler) Finalize(logger log.Logger) (types.Handler, error) {
	// Set Γ = sum_j Γj
	var err error
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	sumGamma := pt.ScalarBaseMult(curve, p.gamma)
	delta := new(big.Int).Mul(p.gamma, p.k)
	chi := new(big.Int).Mul(p.bkMulShare, p.k)
	for id, peer := range p.peers {
		logger = logger.New("peerId", id)
		sumGamma, err = sumGamma.Add(peer.round2Data.allGammaPoint)
		if err != nil {
			logger.Debug("Failed to add gamma", "err")
			return nil, err
		}
		// Compute δi=γiki+ sum_{j!= i}(αi,j+βi,j) mod q and χi=xiki+sum_{j!=0i}(αˆi,j+βˆi,j) mod q.
		delta.Add(delta, peer.round2Data.alpha)
		delta.Add(delta, peer.round1Data.beta)
		delta.Mod(delta, curveN)
		chi.Add(chi, peer.round2Data.alphahat)
		chi.Add(chi, peer.round1Data.betahat)
		chi.Mod(chi, curveN)
	}
	if sumGamma.IsIdentity() {
		logger.Debug("SumGamma is identity")
		return nil, ErrZeroR
	}
	p.sumGamma = sumGamma
	p.delta = delta
	p.chi = chi
	Delta := sumGamma.ScalarMult(p.k)
	p.BigDelta = Delta
	MsgDelta, err := Delta.ToEcPointMessage()
	if err != nil {
		logger.Debug("Failed to ToEcPointMessage", "err", err)
		return nil, err
	}
	for id, peer := range p.peers {
		logger = logger.New("peerId", id)
		peerPed := peer.para
		// Compute proof phi''
		psidoublepaiProof, err := paillierzkproof.NewKnowExponentAndPaillierEncryption(parameter, p.own.ssidWithBk, p.k, p.rho, p.kCiphertext, p.own.para.Getn(), peerPed, Delta, sumGamma)
		if err != nil {
			logger.Debug("Failed to NewKnowExponentAndPaillierEncryption", "err", err)
			return nil, err
		}
		p.peerManager.MustSend(id, &Message{
			Id:   p.own.Id,
			Type: Type_Round3,
			Body: &Message_Round3{
				Round3: &Round3Msg{
					Delta:        delta.String(),
					BigDelta:     MsgDelta,
					Psidoublepai: psidoublepaiProof,
				},
			},
		})
	}
	return newRound3Handler(p)
}
