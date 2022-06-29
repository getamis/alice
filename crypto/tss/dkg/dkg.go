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
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/elliptic"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type DKG struct {
	ph *peerHandler
	*message.MsgMain
}

type Result struct {
	PublicKey *ecpointgrouplaw.ECPoint
	Share     *big.Int
	Bks       map[string]*birkhoffinterpolation.BkParameter
}

func NewDKG(curve elliptic.Curve, peerManager types.PeerManager, threshold uint32, rank uint32, listener types.StateChangedListener) (*DKG, error) {
	peerNum := peerManager.NumPeers()
	if err := ensureRandAndThreshold(rank, threshold, peerNum); err != nil {
		return nil, err
	}
	ph, err := newPeerHandler(curve, peerManager, threshold, rank)
	if err != nil {
		return nil, err
	}
	return &DKG{
		ph:      ph,
		MsgMain: message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, types.MessageType(Type_Peer), types.MessageType(Type_Decommit), types.MessageType(Type_Verify), types.MessageType(Type_Result)),
	}, nil
}

// For testing use
func newDKGWithHandler(peerManager types.PeerManager, threshold uint32, rank uint32, listener types.StateChangedListener, ph *peerHandler) (*DKG, error) {
	peerNum := peerManager.NumPeers()
	if err := ensureRandAndThreshold(rank, threshold, peerNum); err != nil {
		return nil, err
	}
	return &DKG{
		ph:      ph,
		MsgMain: message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, types.MessageType(Type_Peer), types.MessageType(Type_Decommit), types.MessageType(Type_Verify), types.MessageType(Type_Result)),
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
		fmt.Println("Not ready")
		return nil, tss.ErrNotReady
	}

	bks := make(map[string]*birkhoffinterpolation.BkParameter, d.ph.peerManager.NumPeers()+1)
	bks[d.ph.peerManager.SelfID()] = d.ph.bk
	for id, peer := range d.ph.peers {
		bks[id] = peer.peer.bk
	}
	return &Result{
		PublicKey: rh.publicKey,
		Share:     rh.share,
		Bks:       bks,
	}, nil
}

func (d *DKG) Start() {
	d.MsgMain.Start()

	// Send the first message to new peer
	d.ph.broadcast(d.ph.getPeerMessage())
}
