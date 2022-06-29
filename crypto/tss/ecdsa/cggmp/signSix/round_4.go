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

var (
	// ErrZeroS is returned if the s is zero
	ErrZeroS = errors.New("zero s")

	big0 = big.NewInt(0)
)

type round4Data struct {
	allGammaPoint *pt.ECPoint
}

type round4Handler struct {
	*round3Handler

	sumGamma *pt.ECPoint
	BigDelta *pt.ECPoint
}

func newRound4Handler(round3Handler *round3Handler) (*round4Handler, error) {
	return &round4Handler{
		round3Handler: round3Handler,
	}, nil
}

func (p *round4Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round4)
}

func (p *round4Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round4Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round4Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	round4 := msg.GetRound4()
	curve := p.pubKey.GetCurve()
	G := pt.NewBase(curve)
	ownPed := p.own.para
	n := peer.para.Getn()
	Gamma, err := round4.Gamma.ToPoint()
	if err != nil {
		logger.Warn("Failed to ToPoint", "err", err)
		return err
	}
	err = round4.Psipai.Verify(parameter, peer.ssidWithBk, peer.round1Data.gammaCiphertext, n, ownPed, Gamma, G)
	if err != nil {
		logger.Warn("Failed to Verify", "err", err)
		return err
	}
	peer.round4Data = &round4Data{
		allGammaPoint: Gamma,
	}
	return peer.AddMessage(msg)
}

func (p *round4Handler) Finalize(logger log.Logger) (types.Handler, error) {
	// Set Γ = sum_j Γj
	var err error
	curve := p.pubKey.GetCurve()
	sumGamma := pt.ScalarBaseMult(curve, p.gamma)
	for id, peer := range p.peers {
		logger = logger.New("peerId", id)
		sumGamma, err = sumGamma.Add(peer.round4Data.allGammaPoint)
		if err != nil {
			logger.Debug("Failed to add gamma", "err")
			return nil, err
		}
	}
	if sumGamma.IsIdentity() {
		logger.Debug("SumGamma is identity")
		return nil, ErrZeroR
	}
	p.sumGamma = sumGamma
	Delta := sumGamma.ScalarMult(p.k)
	p.BigDelta = Delta
	MsgDelta, err := Delta.ToEcPointMessage()
	if err != nil {
		logger.Debug("Failed to ToEcPointMessage", "err", err)
		return nil, err
	}
	for id := range p.peers {
		logger = logger.New("peerId", id)
		psi, err := paillierzkproof.NewELog(parameter, p.own.ssidWithBk, p.k, p.b, p.Z1, p.Z2, p.own.allY, Delta, sumGamma)
		if err != nil {
			return nil, err
		}
		p.peerManager.MustSend(id, &Message{
			Id:   p.own.Id,
			Type: Type_Round5,
			Body: &Message_Round5{
				Round5: &Round5Msg{
					Delta: MsgDelta,
					Psi:   psi,
				},
			},
		})
	}
	return newRound5Handler(p)
}
