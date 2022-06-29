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

package message

import (
	"bytes"
	"errors"
	"sync"

	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	ErrDifferentHash = errors.New("different hash")
)

type EchoMsgMain struct {
	logger log.Logger
	pm     types.PeerManager
	mu     sync.Mutex
	// keep msgs
	echoMsgs map[types.MessageType]map[string]*echoMessage
	next     types.MessageMain
}

type echoMessage struct {
	hash  []byte
	count uint32
}

func NewEchoMsgMain(next types.MessageMain, pm types.PeerManager, ts ...types.MessageType) types.MessageMain {
	msgs := make(map[types.MessageType]map[string]*echoMessage)
	for _, t := range ts {
		msgs[t] = make(map[string]*echoMessage)
	}
	return &EchoMsgMain{
		logger:   log.New("service", "EchoMsgMain"),
		pm:       pm,
		echoMsgs: msgs,
		next:     next,
	}
}

// NOTE: Avoid duplicate messages from the same peer should be handled in the caller
func (t *EchoMsgMain) AddMessage(msg types.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if not echo messages
	echoMsg, ok := t.echoMsgs[msg.GetMessageType()]
	if !ok {
		return t.next.AddMessage(msg)
	}

	hash, err := msg.Hash()
	if err != nil {
		return err
	}
	mId := msg.GetId()
	m, ok := echoMsg[mId]
	if !ok {
		// Broadcast to other peers
		for _, id := range t.pm.PeerIDs() {
			if mId != id {
				go t.pm.MustSend(id, msg)
			}
		}
		echoMsg[mId] = &echoMessage{
			hash: hash,
		}
		m = echoMsg[mId]
	} else if !bytes.Equal(m.hash, hash) {
		return ErrDifferentHash
	}
	m.count++

	// Not handle if the message count is not enough
	if m.count < t.pm.NumPeers() {
		return nil
	}
	// Clear count
	m.count = 0
	return t.next.AddMessage(msg)
}
