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

// Message defines the message interface
//go:generate mockery --name=EchoMessage
type EchoMessage interface {
	types.Message
	// Hash() return the h
	EchoHash() ([]byte, error)
	// Hash() return the h
	GetEchoMessage() types.Message
}

var (
	ErrNotEchoMsg    = errors.New("not a echo message")
	ErrDifferentHash = errors.New("different hash")
)

type EchoMsgMain struct {
	types.MessageMain

	logger log.Logger
	pm     types.PeerManager
	mu     sync.Mutex
	// keep echo msgs
	// map[message type][the message id]
	echoMsgs map[types.MessageType]map[string]*echoMessage
}

type echoMessage struct {
	hash        []byte
	msgMap      map[string]struct{}
	originalMsg types.Message
}

func NewEchoMsgMain(next types.MessageMain, pm types.PeerManager, ts ...types.MessageType) types.MessageMain {
	msgs := make(map[types.MessageType]map[string]*echoMessage)
	for _, t := range ts {
		msgs[t] = make(map[string]*echoMessage)
	}
	return &EchoMsgMain{
		MessageMain: next,

		logger:   log.New("service", "EchoMsgMain"),
		pm:       pm,
		echoMsgs: msgs,
	}
}

// NOTE: Avoid duplicate messages from the same peer should be handled in the caller
func (t *EchoMsgMain) AddMessage(senderId string, msg types.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if not echo messages
	echoMsg, ok := t.echoMsgs[msg.GetMessageType()]
	if !ok {
		return t.MessageMain.AddMessage(senderId, msg)
	}
	eMsg, ok := msg.(EchoMessage)
	if !ok {
		return ErrNotEchoMsg
	}
	hash, err := eMsg.EchoHash()
	if err != nil {
		return err
	}
	mId := msg.GetId()
	m, ok := echoMsg[mId]
	if !ok {
		// Broadcast to other peers
		for _, id := range t.pm.PeerIDs() {
			if mId != id {
				go t.pm.MustSend(id, eMsg.GetEchoMessage())
			}
		}
		echoMsg[mId] = &echoMessage{
			hash:   hash,
			msgMap: make(map[string]struct{}),
		}
		m = echoMsg[mId]
	} else if !bytes.Equal(m.hash, hash) {
		return ErrDifferentHash
	}
	// If it's an original message
	if senderId == mId && echoMsg[mId].originalMsg == nil {
		m.originalMsg = msg
	}
	m.msgMap[senderId] = struct{}{}

	// Not handle if the message count is not enough
	if len(m.msgMap) < int(t.pm.NumPeers()) || m.originalMsg == nil {
		return nil
	}
	// Clear count
	m.msgMap = make(map[string]struct{})
	return t.MessageMain.AddMessage(m.originalMsg.GetId(), m.originalMsg)
}
