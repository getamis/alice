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

package oldpeer

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type AddShare struct {
	ph *peerHandler
	*message.MsgMain
}

type Result struct {
	PublicKey *ecpointgrouplaw.ECPoint
	Share     *big.Int
	Bks       map[string]*birkhoffinterpolation.BkParameter
}

func NewAddShare(peerManager types.PeerManager, pubkey *ecpointgrouplaw.ECPoint, threshold uint32, share *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, newPeerID string, listener types.StateChangedListener) (*AddShare, error) {
	peerNum := peerManager.NumPeers()
	ph, err := newPeerHandler(peerManager, pubkey, threshold, share, bks, newPeerID)
	if err != nil {
		return nil, err
	}
	return &AddShare{
		ph:      ph,
		MsgMain: message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, types.MessageType(addshare.Type_NewBk), types.MessageType(addshare.Type_Compute), types.MessageType(addshare.Type_Verify)),
	}, nil
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (a *AddShare) GetResult() (*Result, error) {
	if a.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := a.GetHandler()
	ch, ok := h.(*verifyHandler)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	// Total bks = peer bks + self bk + new bk
	bks := make(map[string]*birkhoffinterpolation.BkParameter, a.ph.peerManager.NumPeers()+2)
	bks[a.ph.peerManager.SelfID()] = a.ph.bk
	bks[a.ph.newPeer.Id] = a.ph.newPeer.peer.bk
	for id, peer := range a.ph.peers {
		bks[id] = peer.peer.bk
	}
	return &Result{
		PublicKey: ch.pubkey,
		Share:     ch.share,
		Bks:       bks,
	}, nil
}

func (a *AddShare) Start() {
	a.MsgMain.Start()

	// Send the first message to new peer
	a.ph.peerManager.MustSend(a.ph.newPeer.Id, a.ph.getOldPeerMessage())
}
