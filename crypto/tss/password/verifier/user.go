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

package verifier

import (
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/libs/message"
	"github.com/getamis/alice/libs/message/types"
)

type UserVerifier struct {
	*message.MsgMain

	ph          *userHandler0
	peerManager types.PeerManager
}

func NewUserVerifier(peerManager types.PeerManager, publicKey *ecpointgrouplaw.ECPoint, oldPassword []byte, bks map[string]*birkhoffinterpolation.BkParameter, listener types.StateChangedListener) (*UserVerifier, error) {
	ph, err := newUserHandler0(publicKey, peerManager, bks, oldPassword)
	if err != nil {
		return nil, err
	}

	peerNum := peerManager.NumPeers()
	return &UserVerifier{
		ph:          ph,
		peerManager: peerManager,
		MsgMain:     message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, types.MessageType(Type_MsgServer0), types.MessageType(Type_MsgServer1), types.MessageType(Type_MsgServer2)),
	}, nil
}

func (s *UserVerifier) Start() {
	s.MsgMain.Start()
	message.Broadcast(s.peerManager, s.ph.GetFirstMessage())
}
