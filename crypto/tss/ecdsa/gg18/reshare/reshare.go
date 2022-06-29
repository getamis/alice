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

package reshare

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type Reshare struct {
	ch *commitHandler
	*message.MsgMain
}

type Result struct {
	Share *big.Int
}

func NewReshare(peerManager types.PeerManager, threshold uint32, publicKey *ecpointgrouplaw.ECPoint, oldShare *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, listener types.StateChangedListener) (*Reshare, error) {
	peerNum := peerManager.NumPeers()
	if len(bks) != int(peerNum+1) {
		return nil, tss.ErrNotEnoughBKs
	}
	ch, err := newCommitHandler(publicKey, peerManager, threshold, oldShare, bks)
	if err != nil {
		return nil, err
	}
	return &Reshare{
		ch:      ch,
		MsgMain: message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ch, types.MessageType(Type_Commit), types.MessageType(Type_Verify), types.MessageType(Type_Result)),
	}, nil
}

// GetResult returns the final result: new share
func (d *Reshare) GetResult() (*Result, error) {
	if d.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := d.GetHandler()
	rh, ok := h.(*resultHandler)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	return &Result{
		Share: rh.newShare,
	}, nil
}

func (d *Reshare) Start() {
	d.MsgMain.Start()
	d.ch.broadcast(d.ch.getCommitMessage())
}
