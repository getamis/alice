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

package dkg

import (
	"crypto/elliptic"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/internal/message"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type FirstHandler interface {
	types.Handler

	GetFirstMessage() *Message
	GetPeerHandler() *peerHandler
}

type DKG struct {
	ph          FirstHandler
	peerManager types.PeerManager
	*message.MsgMain
}

type Result struct {
	PublicKey *ecpointgrouplaw.ECPoint
	Share     *big.Int
	Bks       map[string]*birkhoffinterpolation.BkParameter

	// If it's a server DKG, there's a K
	K *big.Int
}

func NewDKG(curve elliptic.Curve, peerManager types.PeerManager, threshold uint32, rank uint32, listener types.StateChangedListener) (*DKG, error) {
	ph, err := newPeerHandler(curve, peerManager, threshold, rank)
	if err != nil {
		return nil, err
	}
	return newDKGWithHandler(peerManager, threshold, rank, listener, ph)
}

func NewPasswordUserDKG(peerManager types.PeerManager, listener types.StateChangedListener, password []byte) (*DKG, error) {
	ph, err := newPasswordPeerUserHandler(peerManager, password)
	if err != nil {
		return nil, err
	}
	return newDKG(peerManager, listener, ph, types.MessageType(Type_OPRFResponse))
}

func NewPasswordServerDKG(peerManager types.PeerManager, listener types.StateChangedListener) (*DKG, error) {
	ph, err := newPasswordPeerServerHandler(peerManager)
	if err != nil {
		return nil, err
	}
	return newDKG(peerManager, listener, ph, types.MessageType(Type_OPRFRequest))
}

// For testing use
func newDKGWithHandler(peerManager types.PeerManager, threshold uint32, rank uint32, listener types.StateChangedListener, ph FirstHandler, msgs ...types.MessageType) (*DKG, error) {
	peerNum := peerManager.NumPeers()
	if err := ensureRandAndThreshold(rank, threshold, peerNum); err != nil {
		return nil, err
	}
	return newDKG(peerManager, listener, ph, msgs...)
}

func newDKG(peerManager types.PeerManager, listener types.StateChangedListener, ph FirstHandler, msgs ...types.MessageType) (*DKG, error) {
	peerNum := peerManager.NumPeers()
	msgs = append(msgs, types.MessageType(Type_Peer), types.MessageType(Type_Decommit), types.MessageType(Type_Verify), types.MessageType(Type_Result))
	return &DKG{
		ph:          ph,
		peerManager: peerManager,
		MsgMain:     message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, msgs...),
	}, nil
}

func ensureRandAndThreshold(rank uint32, threshold uint32, peerNum uint32) error {
	if err := utils.EnsureRank(rank, threshold); err != nil {
		return err
	}
	// the number of attendee is peerNum+1 (add self)
	if err := utils.EnsureThreshold(threshold, peerNum+1); err != nil {
		return err
	}
	return nil
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (d *DKG) GetResult() (*Result, error) {
	if d.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := d.GetHandler()
	rh, ok := h.(*resultHandler)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	bks := make(map[string]*birkhoffinterpolation.BkParameter, d.peerManager.NumPeers()+1)
	ph := d.ph.GetPeerHandler()
	bks[d.peerManager.SelfID()] = ph.bk
	for id, peer := range ph.peers {
		bks[id] = peer.peer.bk
	}
	result := &Result{
		PublicKey: rh.publicKey,
		Share:     rh.share,
		Bks:       bks,
	}

	// Return K if it's a password server handler
	if h, ok := d.ph.(*passwordServerHandler); ok {
		result.K = h.oprfResponser.GetK()
	}
	return result, nil
}

func (d *DKG) Start() {
	d.MsgMain.Start()
	msg := d.ph.GetFirstMessage()
	if msg != nil {
		message.Broadcast(d.peerManager, msg)
	}
}
