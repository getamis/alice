// +build js,wasm
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

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/wasm/message"
	"github.com/golang/protobuf/proto"
)

type peerManager struct {
	id           string
	peers        []string
	sendCallback js.Value
}

func NewPeerManager(id string, peers []string, sendCallback js.Value) *peerManager {
	return &peerManager{
		id:           id,
		peers:        peers,
		sendCallback: sendCallback,
	}
}

func (p *peerManager) NumPeers() uint32 {
	return uint32(len(p.peers))
}

func (p *peerManager) SelfID() string {
	return p.id
}

func (p *peerManager) PeerIDs() []string {
	return p.peers
}

func (p *peerManager) MustSend(peerID string, data interface{}) {
	dkgData, ok := data.(*dkg.Message)
	if !ok {
		return
	}
	msg := &message.Message{
		Type: message.MessageType_DkgMessageType,
		Data: &message.Message_DkgData{
			DkgData: dkgData,
		},
	}
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return
	}
	msgHex := hex.EncodeToString(msgBytes)
	p.sendCallback.Invoke(peerID, msgHex)
}
