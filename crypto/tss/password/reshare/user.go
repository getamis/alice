// Copyright © 2021 AMIS Technologies
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

package reshare

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type UserResult struct {
	PublicKey *ecpointgrouplaw.ECPoint
	Share     *big.Int
	Bks       map[string]*birkhoffinterpolation.BkParameter
}

type UserReshare struct {
	*message.MsgMain

	ph          *userHandler0
	peerManager types.PeerManager
}

func NewUserReshare(peerManager types.PeerManager, publicKey *ecpointgrouplaw.ECPoint, oldPassword []byte, newPassword []byte, bks map[string]*birkhoffinterpolation.BkParameter, listener types.StateChangedListener) (*UserReshare, error) {
	ph, err := newUserHandler0(publicKey, peerManager, bks, oldPassword, newPassword)
	if err != nil {
		return nil, err
	}

	peerNum := peerManager.NumPeers()
	return &UserReshare{
		ph:          ph,
		peerManager: peerManager,
		MsgMain:     message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, types.MessageType(Type_MsgServer0), types.MessageType(Type_MsgServer1), types.MessageType(Type_MsgServer2)),
	}, nil
}

func (s *UserReshare) Start() {
	s.MsgMain.Start()
	message.Broadcast(s.peerManager, s.ph.GetFirstMessage())
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (s *UserReshare) GetResult() (*UserResult, error) {
	if s.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := s.GetHandler()
	rh, ok := h.(*userHandler2)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	return &UserResult{
		PublicKey: rh.publicKey,
		Share:     rh.newShare,
		Bks:       rh.bks,
	}, nil
}
