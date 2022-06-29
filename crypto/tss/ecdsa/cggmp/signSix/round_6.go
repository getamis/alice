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
	paillier "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	big1 = big.NewInt(1)
)

type round6Data struct {
	S *pt.ECPoint
}

type round6Handler struct {
	*round5Handler

	sigma *big.Int

	// Error analysis message
	roundErr2Msg *Message
}

func newRound6Handler(round5Handler *round5Handler) (*round6Handler, error) {
	return &round6Handler{
		round5Handler: round5Handler,
	}, nil
}

func (p *round6Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round6)
}

func (p *round6Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round6Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round6Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	round6 := msg.GetRound6()
	Spoint, err := round6.S.ToPoint()
	if err != nil {
		logger.Warn("Failed to ToPoint", "err", err)
		return err
	}
	// Verify psi
	err = round6.Pi.Verify(parameter, peer.ssidWithBk, peer.round3Data.z1hat, peer.round3Data.z2hat, peer.allY, Spoint, p.R)
	if err != nil {
		logger.Warn("Failed to Verify", "err", err)
		return err
	}
	peer.round6Data = &round6Data{
		S: Spoint,
	}
	return peer.AddMessage(msg)
}

func (p *round6Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	sumS := p.S.Copy()
	var err error
	for _, peer := range p.peers {
		sumS, err = sumS.Add(peer.round6Data.S)
		if err != nil {
			logger.Warn("Failed to Add", "err", err)
			return nil, err
		}
	}

	if !sumS.Equal(p.pubKey) {
		err := p.buildErr2Msg()
		if err != nil {
			logger.Warn("Failed to buildErr1Msg", "err", err)
		}
		return nil, errors.New("failed verification of the public key")
	}

	// Signing
	r := p.R.GetX()
	sigma := new(big.Int).Mul(p.k, new(big.Int).SetBytes(p.msg))
	sigma.Add(sigma, new(big.Int).Mul(r, p.chi))
	sigma.Mod(sigma, curveN)
	p.sigma = sigma
	cggmp.Broadcast(p.peerManager, &Message{
		Id:   p.peerManager.SelfID(),
		Type: Type_Round7,
		Body: &Message_Round7{
			Round7: &Round7Msg{
				Sigma: sigma.Bytes(),
			},
		},
	})
	return newRound7Handler(p)
}

// Error presenter
func (p *round6Handler) buildErr2Msg() error {
	n := p.paillierKey.GetN()
	nsquare := new(big.Int).Mul(n, n)
	nAddone := new(big.Int).Add(n, big1)
	nthRoot, err := p.paillierKey.GetNthRoot()
	if err != nil {
		return err
	}
	rhoNPower := new(big.Int).Exp(p.rho, n, nsquare)
	curve := p.pubKey.GetCurve()
	psi, err := paillier.NewNthRoot(paillier.NewS256(), p.own.ssidWithBk, p.rho, rhoNPower, n)
	if err != nil {
		return err
	}
	G := pt.NewBase(curve)
	biG := G.ScalarMult(p.bhat)
	Y := p.own.allY
	biY := Y.ScalarMult(p.bhat)
	psipai, err := paillier.NewLog(p.own.ssidWithBk, p.bhat, G, Y, biG, biY)
	if err != nil {
		return err
	}
	biYMsg, err := biY.ToEcPointMessage()
	if err != nil {
		return err
	}

	// build peersMsg
	peersMsg := make(map[string]*Err2PeerMsg, len(p.peers))
	for _, peer := range p.peers {
		muij := new(big.Int).Exp(nAddone, new(big.Int).Neg(peer.round2Data.alphahat), nsquare)
		muij.Mul(muij, peer.round2Data.dhat)
		muNthPower := new(big.Int).Mod(muij, nsquare)
		mu := muij.Exp(muNthPower, nthRoot, nsquare)
		muNPower := muNthPower
		psiMuProof, err := paillier.NewNthRoot(paillier.NewS256(), p.own.ssidWithBk, mu, muNPower, n)
		if err != nil {
			return err
		}
		peersMsg[peer.Id] = &Err2PeerMsg{
			Alphahat:    peer.round2Data.alphahat.Bytes(),
			MuhatNPower: muNPower.Bytes(),
			PsiMuProof:  psiMuProof,
		}
	}

	p.roundErr2Msg = &Message{
		Id:   p.own.Id,
		Type: Type_Err1,
		Body: &Message_Err2{
			Err2: &Err2Msg{
				K:           p.k.Bytes(),
				RhoNPower:   rhoNPower.Bytes(),
				PsiRhoProof: psi,
				PsipaiProof: psipai,
				Ytilde:      biYMsg,
				Peers:       peersMsg,
			},
		},
	}
	return nil
}

func (p *round6Handler) ProcessErr2Msg(msgs []*Message) (map[string]struct{}, error) {
	curve := p.pubKey.GetCurve()
	G := pt.NewBase(curve)
	errPeers := make(map[string]struct{})
	for i, m := range msgs {
		peerId := m.GetId()
		peer, ok := p.peers[peerId]
		if !ok {
			continue
		}
		msg := m.GetErr2()
		if msg == nil {
			errPeers[peerId] = struct{}{}
			continue
		}
		n := peer.para.Getn()
		nSquare := new(big.Int).Mul(n, n)
		biY, err := msg.Ytilde.ToPoint()
		if err != nil {
			errPeers[peerId] = struct{}{}
			continue
		}

		err = msg.PsipaiProof.Verify(peer.ssidWithBk, G, peer.allY, peer.round3Data.z1hat, biY)
		if err != nil {
			errPeers[peerId] = struct{}{}
			continue
		}

		RhoNPower := new(big.Int).SetBytes(msg.RhoNPower)
		err = msg.PsiRhoProof.Verify(paillier.NewS256(), peer.ssidWithBk, RhoNPower, n)
		if err != nil {
			errPeers[peerId] = struct{}{}
			continue
		}
		// Check Kj = (1+nj)^kj * rhoNPower
		compareK := new(big.Int).Exp(new(big.Int).Add(big1, n), new(big.Int).SetBytes(msg.K), nSquare)
		compareK.Mul(compareK, RhoNPower)
		compareK.Mod(compareK, nSquare)
		if compareK.Cmp(peer.round1Data.kCiphertext) != 0 {
			errPeers[peerId] = struct{}{}
			continue
		}

		// sum_{j!=ell} alpha_{j,ell}
		Xj := peer.partialPubKey
		compare := Xj.ScalarMult(new(big.Int).SetBytes(msg.K))
		for checkPeerId, peerMsg := range msg.Peers {
			muNPower := new(big.Int).SetBytes(peerMsg.MuhatNPower)
			err = peerMsg.PsiMuProof.Verify(paillier.NewS256(), peer.ssidWithBk, muNPower, n)
			if err != nil {
				errPeers[peerId] = struct{}{}
				continue
			}

			// check Dj,k = (1+Nj)^αj * kμ ̃j,k mod Nj^2
			if checkPeerId == p.own.Id {
				alpha := new(big.Int).SetBytes(peerMsg.Alphahat)
				verifyghat := new(big.Int).Exp(new(big.Int).Add(big1, n), alpha, nSquare)
				verifyghat.Mul(verifyghat, muNPower)
				verifyghat.Mod(verifyghat, nSquare)

				D := new(big.Int).SetBytes(peer.round1Data.Dhat)
				if D.Cmp(verifyghat) != 0 {
					errPeers[peerId] = struct{}{}
					continue
				}
			}

			temp := G.ScalarMult(new(big.Int).SetBytes(peerMsg.Alphahat))
			compare, err = compare.Add(temp)
			if err != nil {
				errPeers[peerId] = struct{}{}
				continue
			}
		}
		// check Mj −Y ̃j =kj ·Xj +sum_{ell != j} αˆj,l·G+kl·Xj −αˆl,j ·G.
		YInverseM, err := msg.Ytilde.ToPoint()
		if err != nil {
			errPeers[peerId] = struct{}{}
			continue
		}
		YInverseM, err = peer.round3Data.z2hat.Add(YInverseM.Neg())
		if err != nil {
			errPeers[peerId] = struct{}{}
			continue
		}

		tempPt := Xj.ScalarMult(p.k)
		tempPt, err = tempPt.Add(G.ScalarMult(peer.round2Data.alphahat).Neg())
		if err != nil {
			errPeers[peerId] = struct{}{}
			continue
		}
		compare, err = compare.Add(tempPt)
		if err != nil {
			errPeers[peerId] = struct{}{}
			continue
		}

		for j, m2 := range msgs {
			if i == j {
				continue
			}
			msg2 := m2.GetErr2()
			got, ok := msg2.Peers[peerId]
			if !ok {
				errPeers[peerId] = struct{}{}
				continue
			}

			temp := Xj.ScalarMult(new(big.Int).SetBytes(msg2.K))
			temp, err = temp.Add(G.ScalarMult(new(big.Int).SetBytes(got.Alphahat)).Neg())
			if err != nil {
				errPeers[peerId] = struct{}{}
				continue
			}
			compare, err = compare.Add(temp)
			if err != nil {
				errPeers[peerId] = struct{}{}
				continue
			}
		}
		if !compare.Equal(YInverseM) {
			errPeers[peerId] = struct{}{}
			continue
		}
	}
	return errPeers, nil
}
