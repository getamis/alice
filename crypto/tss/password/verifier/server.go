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
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/message"
	"github.com/getamis/alice/crypto/tss/message/types"
)

type ServerVerifier struct {
	*message.MsgMain

	ph          *serverHandler0
	peerManager types.PeerManager
}

func NewServerVerifier(peerManager types.PeerManager, publicKey *ecpointgrouplaw.ECPoint, k *big.Int, secret *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, listener types.StateChangedListener) (*ServerVerifier, error) {
	ph, err := newServerHandler0(publicKey, peerManager, bks, k, secret)
	if err != nil {
		return nil, err
	}

	peerNum := peerManager.NumPeers()
	return &ServerVerifier{
		ph:          ph,
		peerManager: peerManager,
		MsgMain:     message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, types.MessageType(Type_MsgUser0), types.MessageType(Type_MsgUser1), types.MessageType(Type_MsgUser2), types.MessageType(Type_MsgUser3)),
	}, nil
}
