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
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type round5Data struct {
	delta *pt.ECPoint
	rbar  *pt.ECPoint
}

type round5Handler struct {
	*round4Handler

	R *pt.ECPoint
	S *pt.ECPoint

	// Error analysis message
	roundErr1Msg *Message
}

func newRound5Handler(round4Handler *round4Handler) (*round5Handler, error) {
	return &round5Handler{
		round4Handler: round4Handler,
	}, nil
}

func (p *round5Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round5)
}

func (p *round5Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round5Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round5Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	round5 := msg.GetRound5()
	delta, err := round5.Delta.ToPoint()
	if err != nil {
		logger.Warn("Failed to ToPoint", "err", err)
		return err
	}

	// Verify psi
	err = round5.Psi.Verify(parameter, peer.ssidWithBk, peer.round1Data.Z1, peer.round1Data.Z2, peer.allY, delta, p.sumGamma)
	if err != nil {
		logger.Warn("Failed to Verify", "err", err)
		return err
	}

	peer.round5Data = &round5Data{
		delta: delta,
	}
	return peer.AddMessage(msg)
}

func (p *round5Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	G := pt.NewBase(curve)
	sumdelta := new(big.Int).Set(p.delta)
	sumDeltaPoint := p.BigDelta.Copy()
	var err error
	for _, peer := range p.peers {
		sumDeltaPoint, err = sumDeltaPoint.Add(peer.round5Data.delta)
		if err != nil {
			logger.Warn("Failed to Add", "err", err)
			return nil, err
		}
		sumdelta.Add(sumdelta, peer.round3Data.delta)
	}
	inverseSumDelta := new(big.Int).ModInverse(sumdelta, curveN)
	R := p.sumGamma.ScalarMult(inverseSumDelta)
	if R.IsIdentity() {
		logger.Warn("Identity point")
		return nil, ErrZeroR
	}

	if !G.ScalarMult(sumdelta).Equal(sumDeltaPoint) {
		err := p.buildErr1Msg()
		if err != nil {
			logger.Warn("Failed to buildErr1Msg", "err", err)
		}
		return nil, errors.New("failed verify")
	}
	p.R = R

	RchiPoint := R.ScalarMult(p.chi)
	msgRchiPoint, err := RchiPoint.ToEcPointMessage()
	if err != nil {
		logger.Warn("Failed to ToEcPointMessage", "err", err)
		return nil, err
	}
	p.S = RchiPoint

	for _, peer := range p.peers {
		psi, err := paillierzkproof.NewELog(parameter, p.own.ssidWithBk, p.chi, p.bhat, p.Z1Hat, p.Z2Hat, p.own.allY, RchiPoint, p.R)
		if err != nil {
			logger.Warn("Failed to NewELog", "err", err)
			return nil, err
		}
		peer.round5Data.rbar = peer.round5Data.delta.ScalarMult(inverseSumDelta)
		p.peerManager.MustSend(peer.Id, &Message{
			Id:   p.own.Id,
			Type: Type_Round6,
			Body: &Message_Round6{
				Round6: &Round6Msg{
					S:  msgRchiPoint,
					Pi: psi,
				},
			},
		})
	}
	return newRound6Handler(p)
}

func (p *round5Handler) buildErr1Msg() error {
	n := p.paillierKey.GetN()
	nsquare := new(big.Int).Mul(n, n)
	nAddone := new(big.Int).Add(n, big1)
	nthRoot, err := p.paillierKey.GetNthRoot()
	if err != nil {
		return err
	}
	rhoNPower := new(big.Int).Exp(p.rho, n, nsquare)
	psi, err := paillierzkproof.NewNthRoot(paillierzkproof.NewS256(), p.own.ssidWithBk, p.rho, rhoNPower, n)
	if err != nil {
		return err
	}
	// build peersMsg
	peersMsg := make(map[string]*Err1PeerMsg, len(p.peers))
	for _, peer := range p.peers {
		muij := new(big.Int).Exp(nAddone, new(big.Int).Neg(peer.round2Data.alpha), nsquare)
		muij.Mul(muij, peer.round2Data.d)
		muNthPower := new(big.Int).Mod(muij, nsquare)
		mu := muij.Exp(muNthPower, nthRoot, nsquare)
		muNPower := muNthPower
		psiMuProof, err := paillierzkproof.NewNthRoot(paillierzkproof.NewS256(), p.own.ssidWithBk, mu, muNPower, n)
		if err != nil {
			return err
		}

		peersMsg[peer.Id] = &Err1PeerMsg{
			Alpha:      peer.round2Data.alpha.Bytes(),
			MuNPower:   muNPower.Bytes(),
			PsiMuProof: psiMuProof,
		}
	}

	p.roundErr1Msg = &Message{
		Id:   p.own.Id,
		Type: Type_Err1,
		Body: &Message_Err1{
			Err1: &Err1Msg{
				K:           p.k.Bytes(),
				RhoNPower:   rhoNPower.Bytes(),
				PsiRhoProof: psi,
				Gamma:       p.gamma.Bytes(),
				Peers:       peersMsg,
			},
		},
	}
	return nil
}

func (p *round5Handler) ProcessErr1Msg(msgs []*Message) (map[string]struct{}, error) {
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	G := pt.NewBase(curve)
	errPeers := make(map[string]struct{})
	for i, m := range msgs {
		peerId := m.GetId()
		peer, ok := p.peers[peerId]
		if !ok {
			continue
		}
		msg := m.GetErr1()
		if msg == nil {
			errPeers[peerId] = struct{}{}
			continue
		}
		n := peer.para.Getn()
		nSquare := new(big.Int).Mul(n, n)

		rhoNPower := new(big.Int).SetBytes(msg.RhoNPower)
		err := msg.PsiRhoProof.Verify(paillierzkproof.NewS256(), peer.ssidWithBk, rhoNPower, n)
		if err != nil {
			errPeers[peerId] = struct{}{}
			continue
		}

		// Check Kj = (1+nj)^kj * rhoNPower
		k := new(big.Int).SetBytes(msg.K)
		verifyKCiphertext := new(big.Int).Exp(new(big.Int).Add(big1, n), k, nSquare)
		verifyKCiphertext.Mul(verifyKCiphertext, rhoNPower)
		verifyKCiphertext.Mod(verifyKCiphertext, nSquare)
		KCiphertext := peer.round1Data.kCiphertext
		if KCiphertext.Cmp(verifyKCiphertext) != 0 {
			errPeers[peerId] = struct{}{}
			continue
		}

		// sum_{j!=ell} alpha_{j,ell}
		delta := new(big.Int).Mul(k, new(big.Int).SetBytes(msg.Gamma))
		for checkPeerId, peerMsg := range msg.Peers {
			muNPower := new(big.Int).SetBytes(peerMsg.MuNPower)
			err = peerMsg.PsiMuProof.Verify(paillierzkproof.NewS256(), peer.ssidWithBk, muNPower, n)
			if err != nil {
				errPeers[peerId] = struct{}{}
				continue
			}
			// check Dj,k = (1+Nj)^αj * kμ ̃j,k mod Nj^2
			if checkPeerId == p.own.Id {
				alpha := new(big.Int).SetBytes(peerMsg.Alpha)
				verfigyD := new(big.Int).Exp(new(big.Int).Add(big1, n), alpha, nSquare)
				verfigyD.Mul(verfigyD, muNPower)
				verfigyD.Mod(verfigyD, nSquare)
				// Should be round1
				D := peer.round1Data.D
				if D.Cmp(verfigyD) != 0 {
					errPeers[peerId] = struct{}{}
					continue
				}
			}

			delta.Add(delta, new(big.Int).SetBytes(peerMsg.Alpha))
		}
		// check γjG = Γj
		gammaG := peer.round4Data.allGammaPoint
		compareGammaG := G.ScalarMult(new(big.Int).SetBytes(msg.Gamma))
		if !gammaG.Equal(compareGammaG) {
			errPeers[peerId] = struct{}{}
			continue
		}
		// check δj=kjγj+ sum_{l \not= j} (αj,l+kl*γj−αl,j) mod q.
		// kiγj - αi,j
		gamma := new(big.Int).SetBytes(msg.Gamma)
		tempValue := new(big.Int).Mul(p.k, gamma)
		delta.Add(delta, tempValue.Sub(tempValue, peer.round2Data.alpha))
		delta.Mod(delta, curveN)

		for j, m2 := range msgs {
			if i == j {
				continue
			}
			msg2 := m2.GetErr1()
			got, ok := msg2.Peers[peerId]
			if !ok {
				errPeers[peerId] = struct{}{}
				continue
			}
			temp := new(big.Int).Mul(new(big.Int).SetBytes(msg2.K), gamma)
			temp.Sub(temp, new(big.Int).SetBytes(got.Alpha))
			delta.Add(delta, temp)
			delta.Mod(delta, curveN)
		}

		if peer.round3Data.delta.Cmp(delta) != 0 {
			errPeers[peerId] = struct{}{}
			continue
		}
	}
	return errPeers, nil
}
