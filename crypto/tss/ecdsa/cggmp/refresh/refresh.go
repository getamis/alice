// Copyright © 2022 AMIS Technologies
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

package refresh

import (
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type Refresh struct {
	ph *round1Handler
	*message.MsgMain

	msgMainer types.MessageMain
}

func NewRefresh(pubKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, threshold uint32, bks map[string]*birkhoffinterpolation.BkParameter, keySize int, ssid []byte, listener types.StateChangedListener) (*Refresh, error) {
	peerNum := peerManager.NumPeers()
	ph, err := newRound1Handler(pubKey, peerManager, threshold, bks, keySize, ssid)
	if err != nil {
		return nil, err
	}
	ms := message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, types.MessageType(Type_Round1), types.MessageType(Type_Round2), types.MessageType(Type_Round3))
	msgMainer := message.NewEchoMsgMain(ms, peerManager, types.MessageType(Type_Round1), types.MessageType(Type_Round2))
	return &Refresh{
		ph:        ph,
		MsgMain:   ms,
		msgMainer: msgMainer,
	}, nil
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (d *Refresh) GetResult() (*Result, error) {
	if d.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := d.GetHandler()
	rh, ok := h.(*round3Handler)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	return rh.result, nil
}

func (d *Refresh) AddMessage(msg types.Message) error {
	return d.msgMainer.AddMessage(msg)
}

func (d *Refresh) Start() {
	d.MsgMain.Start()

	// Send the first message to new peer
	cggmp.Broadcast(d.ph.peerManager, d.ph.getRound1Message())
}
