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
	"github.com/getamis/alice/internal/message/types"
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
		// Do analysis
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
