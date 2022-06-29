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
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type Result struct {
	R *big.Int
	S *big.Int
}

type round7Data struct {
	Sigma *big.Int
}

type round7Handler struct {
	*round6Handler

	result *Result
}

func newRound7Handler(round6Handler *round6Handler) (*round7Handler, error) {
	return &round7Handler{
		round6Handler: round6Handler,
	}, nil
}

func (p *round7Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round7)
}

func (p *round7Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round7Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round7Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	round7 := msg.GetRound7()
	peer.round7Data = &round7Data{
		Sigma: new(big.Int).SetBytes(round7.Sigma),
	}
	return peer.AddMessage(msg)
}

func (p *round7Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N

	s := new(big.Int).Set(p.sigma)
	for _, peer := range p.peers {
		s.Add(s, peer.round7Data.Sigma)
		s.Mod(s, curveN)
	}
	if s.Cmp(big0) == 0 {
		return nil, ErrZeroS
	}
	isCorrectSig := ecdsa.Verify(p.pubKey.ToPubKey(), p.msg, p.R.GetX(), s)

	// TODO: Error message collect
	if !isCorrectSig {
		return nil, errors.New("failed verified")
	}
	p.result = &Result{
		R: p.R.GetX(),
		S: s,
	}
	return nil, nil
}
