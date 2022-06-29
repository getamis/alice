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

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
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
		types.MessageType(Type_Commitment),
		types.MessageType(Type_Decommitment),
		types.MessageType(Type_Result),
		types.MessageType(Type_Verify),
	}
)

type Result struct {
	PublicKey *ecpointgrouplaw.ECPoint
	Share     *big.Int
	Bks       map[string]*birkhoffinterpolation.BkParameter
	Seed      []byte
	ChainCode []byte
}

type Master struct {
	*message.MsgMain

	ih *initial
}

// sid/aliceSeed
func NewAlice(peerManager types.PeerManager, sid []uint8, rank uint32, path string, listener types.StateChangedListener) (*Master, error) {
	seed, err := utils.GenRandomBytes(SeedLength)
	if err != nil {
		log.Warn("Failed to random a seed", "err", err)
		return nil, err
	}
	return newAlice(peerManager, sid, seed, rank, path, listener)
}
func newAlice(peerManager types.PeerManager, sid []uint8, seed []byte, rank uint32, path string, listener types.StateChangedListener) (*Master, error) {
	numPeers := peerManager.NumPeers()
	ih, err := newAliceMasterKey(peerManager, sid, seed, rank, path)
	if err != nil {
		log.Warn("Failed to new alice", "err", err)
		return nil, err
	}
	return &Master{
		ih: ih,
		MsgMain: message.NewMsgMain(peerManager.SelfID(),
			numPeers,
			listener,
			ih,
			msgTypes...,
		),
	}, nil
}

func NewBob(peerManager types.PeerManager, sid []uint8, rank uint32, path string, listener types.StateChangedListener) (*Master, error) {
	seed, err := utils.GenRandomBytes(SeedLength)
	if err != nil {
		log.Warn("Failed to random a seed", "err", err)
		return nil, err
	}
	return newBob(peerManager, sid, seed, rank, path, listener)
}

func newBob(peerManager types.PeerManager, sid []uint8, seed []byte, rank uint32, path string, listener types.StateChangedListener) (*Master, error) {
	numPeers := peerManager.NumPeers()
	ih, err := newBobMasterKey(peerManager, sid, seed, rank, path)
	if err != nil {
		log.Warn("Failed to new bob", "err", err)
		return nil, err
	}
	return &Master{
		ih: ih,
		MsgMain: message.NewMsgMain(peerManager.SelfID(),
			numPeers,
			listener,
			ih,
			msgTypes...,
		),
	}, nil
}

func (m *Master) Start() {
	m.MsgMain.Start()
	m.ih.broadcast(m.ih.GetFirstMessage())
}

func (m *Master) GetResult() (*Result, error) {
	if m.GetState() != types.StateDone {
		return nil, ErrNotReady
	}

	h := m.GetHandler()
	rh, ok := h.(*verifyHandler)
	if !ok {
		log.Error("We cannot convert to otSendResponse handler in done state")
		return nil, ErrNotReady
	}
	bks := make(map[string]*birkhoffinterpolation.BkParameter, m.ih.peerNum+1)
	bks[m.ih.selfId] = m.ih.bk
	for id, peer := range m.ih.peers {
		bks[id] = peer.bk
	}
	return &Result{
		PublicKey: rh.publicKey,
		Share:     rh.share,
		Bks:       bks,
		ChainCode: rh.chiancode,
		Seed:      rh.seed,
	}, nil
}
