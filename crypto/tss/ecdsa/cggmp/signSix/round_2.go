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

package signSix

import (
	"errors"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/utils"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	// ErrZeroR is returned if the r is zero
	ErrZeroR = errors.New("zero r")
)

type round2Data struct {
	psihatProoof *paillierzkproof.PaillierAffAndGroupRangeMessage
	d            *big.Int
	f            *big.Int
	dhat         *big.Int
	fhat         *big.Int
	alpha        *big.Int
	alphahat     *big.Int
}

type round2Handler struct {
	*round1Handler

	delta       *big.Int
	chi         *big.Int
	sumMTAAlpha *big.Int

	bhat  *big.Int
	Z1Hat *pt.ECPoint
	Z2Hat *pt.ECPoint
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
	ownPed := p.own.para
	n := peer.para.Getn()
	// Verify psi
	err := round2.Psi.Verify(parameter, peer.ssidWithBk, p.paillierKey.GetN(), n, p.kCiphertext, new(big.Int).SetBytes(round2.D), peer.round1Data.gammaCiphertext, new(big.Int).SetBytes(round2.F), ownPed)
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

	alpha, err := p.paillierKey.Decrypt(round2.D)
	if err != nil {
		return err
	}
	alphahat, err := p.paillierKey.Decrypt(round2.Dhat)
	if err != nil {
		return err
	}
	peer.round2Data = &round2Data{
		d:            new(big.Int).SetBytes(round2.D),
		f:            new(big.Int).SetBytes(round2.F),
		psihatProoof: round2.Psihat,
		dhat:         new(big.Int).SetBytes(round2.Dhat),
		fhat:         new(big.Int).SetBytes(round2.Fhat),
		alpha:        new(big.Int).SetBytes(alpha),
		alphahat:     new(big.Int).SetBytes(alphahat),
	}
	return peer.AddMessage(msg)
}

func (p *round2Handler) Finalize(logger log.Logger) (types.Handler, error) {
	// Set Γ = sum_j Γj
	var err error
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	G := pt.NewBase(curve)
	delta := new(big.Int).Mul(p.gamma, p.k)
	chi := new(big.Int).Mul(p.bkMulShare, p.k)
	sumMTAAlpha := big.NewInt(0)
	for id, peer := range p.peers {
		logger = logger.New("peerId", id)
		// Use this value in Failure part.
		sumMTAAlpha.Add(sumMTAAlpha, peer.round2Data.alpha)

		delta.Add(delta, peer.round2Data.alpha)
		delta.Add(delta, peer.round1Data.beta)
		delta.Mod(delta, curveN)
		chi.Add(chi, peer.round2Data.alphahat)
		chi.Add(chi, peer.round1Data.betahat)
		chi.Mod(chi, curveN)
	}
	p.delta = delta
	p.chi = chi
	p.sumMTAAlpha = sumMTAAlpha

	bhat, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}
	Zhat1 := G.ScalarMult(bhat)
	Zhat2 := G.ScalarMult(chi)
	Zhat2, err = Zhat2.Add((p.own.allY).ScalarMult(bhat))
	if err != nil {
		return nil, err
	}
	msgZhat1, err := Zhat1.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgZhat2, err := Zhat2.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	p.bhat = bhat
	p.Z1Hat = Zhat1
	p.Z2Hat = Zhat2

	cggmp.Broadcast(p.peerManager, &Message{
		Id:   p.own.Id,
		Type: Type_Round3,
		Body: &Message_Round3{
			Round3: &Round3Msg{
				Delta: delta.Bytes(),
				Z1Hat: msgZhat1,
				Z2Hat: msgZhat2,
			},
		},
	})
	return newRound3Handler(p)
}
