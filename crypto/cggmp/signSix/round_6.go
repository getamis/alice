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

	"github.com/getamis/alice/crypto/cggmp"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type round6Data struct {
	S *pt.ECPoint
}

type round6Handler struct {
	*round5Handler

	sigma *big.Int
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
