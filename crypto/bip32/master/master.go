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

package master

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/internal/message"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

var (
	ErrNotReady = errors.New("not ready")
)

type Master struct {
	*message.MsgMain

	ih *initial
	pm types.PeerManager
}

// sid/aliceSeed
func NewAlice(peerManager types.PeerManager, sid []uint8, seed []uint8, path string, listener types.StateChangedListener) (*Master, error) {
	numPeers := peerManager.NumPeers()
	ih, err := newAliceMasterKey(peerManager, sid, seed, path)
	if err != nil {
		log.Warn("Failed to new a public key handler", "err", err)
		return nil, err
	}
	return &Master{
		ih: ih,
		MsgMain: message.NewMsgMain(peerManager.SelfID(),
			numPeers,
			listener,
			ih,
			types.MessageType(Type_Initial),
			types.MessageType(Type_OtReceiver),
			types.MessageType(Type_OtSendResponse),
		),
	}, nil
}

func NewBob(peerManager types.PeerManager, sid []uint8, ownSeedBit []uint8, path string, listener types.StateChangedListener) (*Master, error) {
	numPeers := peerManager.NumPeers()
	ih, err := newBobMasterKey(peerManager, sid, ownSeedBit, path)
	if err != nil {
		log.Warn("Failed to new a public key handler", "err", err)
		return nil, err
	}
	return &Master{
		ih: ih,
		MsgMain: message.NewMsgMain(peerManager.SelfID(),
			numPeers,
			listener,
			ih,
			types.MessageType(Type_Initial),
			types.MessageType(Type_OtReceiver),
			types.MessageType(Type_OtSendResponse),
		),
	}, nil
}

func (m *Master) Start() {
	m.MsgMain.Start()
	m.ih.broadcast(m.ih.GetFirstMessage())
}

func (m *Master) GetResult() ([]byte, *big.Int, error) {
	if m.GetState() != types.StateDone {
		return nil, nil, ErrNotReady
	}

	h := m.GetHandler()
	rh, ok := h.(*otSendResponse)
	if !ok {
		log.Error("We cannot convert to otSendResponse handler in done state")
		return nil, nil, ErrNotReady
	}

	return rh.chiancode, rh.randomChoose, nil
}
