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
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type SiResult struct {
	R  *pt.ECPoint
	Si *big.Int
}

type SiSigner struct {
	*Signer
}

func NewSiSigner(peerManager types.PeerManager, expectedPubkey *pt.ECPoint, homo homo.Crypto, secret *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte, listener types.StateChangedListener) (*SiSigner, error) {
	ph, err := newPubkeyHandler(expectedPubkey, peerManager, homo, secret, bks, msg, false)
	if err != nil {
		log.Debug("Failed to new a public key handler", "err", err)
		return nil, err
	}
	s, err := newSigner(peerManager, listener, ph)
	if err != nil {
		log.Debug("Failed to new signers", "err", err)
	}
	return &SiSigner{
		Signer: s,
	}, nil
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (s *SiSigner) GetResult() (*SiResult, error) {
	if s.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := s.GetHandler()
	rh, ok := h.(*decommitUiTiHandler)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	return &SiResult{
		R:  rh.r.Copy(),
		Si: new(big.Int).Set(rh.si),
	}, nil
}
