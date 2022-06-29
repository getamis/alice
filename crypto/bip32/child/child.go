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

package child

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

var (
	ErrNotReady = errors.New("not ready")

	msgTypes = []types.MessageType{
		types.MessageType(Type_Initial),
		types.MessageType(Type_OtReceiver),
		types.MessageType(Type_OtSendResponse),
		types.MessageType(Type_EncH),
		types.MessageType(Type_Sh2Hash),
	}
)

type Result struct {
	Translate *big.Int
	PublicKey *ecpointgrouplaw.ECPoint
	ChainCode []byte
	Depth     byte
}

type Child struct {
	*message.MsgMain

	ih *initial
}

func NewAlice(peerManager types.PeerManager, sid []uint8, share *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, path string, chainCode []byte, depth uint8, childIndex uint32, pubKey *ecpointgrouplaw.ECPoint, listener types.StateChangedListener) (*Child, error) {
	numPeers := peerManager.NumPeers()
	ih, err := newAliceChildKey(peerManager, share, bks, sid, path, chainCode, depth, childIndex, pubKey)
	if err != nil {
		log.Warn("Failed to new alice", "err", err)
		return nil, err
	}
	return &Child{
		ih: ih,
		MsgMain: message.NewMsgMain(peerManager.SelfID(),
			numPeers,
			listener,
			ih,
			msgTypes...,
		),
	}, nil
}

func NewBob(peerManager types.PeerManager, sid []uint8, share *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, path string, chainCode []byte, depth uint8, childIndex uint32, pubKey *ecpointgrouplaw.ECPoint, listener types.StateChangedListener) (*Child, error) {
	numPeers := peerManager.NumPeers()
	ih, err := newBobChildKey(peerManager, share, bks, sid, path, chainCode, depth, childIndex, pubKey)
	if err != nil {
		log.Warn("Failed to new alice", "err", err)
		return nil, err
	}
	if err != nil {
		log.Warn("Failed to new bob", "err", err)
		return nil, err
	}
	return &Child{
		ih: ih,
		MsgMain: message.NewMsgMain(peerManager.SelfID(),
			numPeers,
			listener,
			ih,
			msgTypes...,
		),
	}, nil
}

func (m *Child) Start() {
	m.MsgMain.Start()
	m.ih.broadcast(m.ih.GetFirstMessage())
}

func (m *Child) GetResult() (*Result, error) {
	if m.GetState() != types.StateDone {
		return nil, ErrNotReady
	}

	h := m.GetHandler()
	rh, ok := h.(*sh2Hash)
	if !ok {
		log.Error("We cannot convert to otSendResponse handler in done state")
		return nil, ErrNotReady
	}
	return &Result{
		Translate: rh.childShare.translate,
		PublicKey: rh.childShare.publicKey,
		ChainCode: rh.childShare.chainCode,
		Depth:     rh.childShare.depth,
	}, nil
}
