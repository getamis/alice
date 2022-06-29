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

package signer

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type Result struct {
	R *ecpointgrouplaw.ECPoint
	S *big.Int
}

type Signer struct {
	ph *round1
	*message.MsgMain
}

func NewSigner(pubKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, threshold uint32, share *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte, listener types.StateChangedListener) (*Signer, error) {
	numPeers := peerManager.NumPeers()
	ph, err := newRound1(pubKey, peerManager, threshold, share, bks, msg)
	if err != nil {
		log.Warn("Failed to new a public key handler", "err", err)
		return nil, err
	}
	return &Signer{
		ph: ph,
		MsgMain: message.NewMsgMain(peerManager.SelfID(),
			numPeers,
			listener,
			ph,
			types.MessageType(Type_Round1),
			types.MessageType(Type_Round2),
		),
	}, nil
}

func (s *Signer) Start() {
	s.MsgMain.Start()

	// Send the first message to new peer
	cggmp.Broadcast(s.ph.peerManager, s.ph.round1Msg)
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (s *Signer) GetResult() (*Result, error) {
	if s.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := s.GetHandler()
	rh, ok := h.(*round2)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	return &Result{
		R: rh.r,
		S: new(big.Int).Set(rh.s),
	}, nil
}
