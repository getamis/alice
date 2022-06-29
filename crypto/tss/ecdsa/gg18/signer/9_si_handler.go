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

	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	big0 = big.NewInt(0)

	// ErrZeroS is returned if the s is zero
	ErrZeroS = errors.New("zero s")
)

type siData struct {
	si *big.Int
}

type siHandler struct {
	*decommitUiTiHandler
	s *big.Int
}

func newSiHandler(p *decommitUiTiHandler) (*siHandler, error) {
	return &siHandler{
		decommitUiTiHandler: p,
	}, nil
}

func (p *siHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Si)
}

func (p *siHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *siHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.si != nil
}

func (p *siHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetSi()
	peer.si = &siData{
		si: new(big.Int).SetBytes(body.GetSi()),
	}
	return peer.AddMessage(msg)
}

func (p *siHandler) Finalize(logger log.Logger) (types.Handler, error) {
	p.s = new(big.Int).Set(p.si)
	for _, peer := range p.peers {
		p.s = new(big.Int).Add(p.s, peer.si.si)
	}
	p.s.Mod(p.s, p.getCurve().Params().N)
	if p.s.Cmp(big0) == 0 {
		return nil, ErrZeroS
	}
	return nil, nil
}
