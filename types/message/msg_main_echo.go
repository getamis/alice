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
	"github.com/minio/blake2b-simd"
	"google.golang.org/protobuf/proto"
)

// Message defines the message interface
//
//go:generate mockery --name=EchoMessage
type EchoMessage interface {
	proto.Message
	types.Message
	// GetEchoMessage() return the message to broadcast in echo protocol
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

	marshalFunc func(m proto.Message) ([]byte, error)
}

type echoMessage struct {
	hash        []byte
	msgMap      map[string]struct{}
	originalMsg types.Message
}

func NewEchoMsgMain(next types.MessageMain, pm types.PeerManager) *EchoMsgMain {
	msgs := make(map[types.MessageType]map[string]*echoMessage)
	return &EchoMsgMain{
		MessageMain: next,

		logger:      log.New("service", "EchoMsgMain"),
		pm:          pm,
		echoMsgs:    msgs,
		marshalFunc: proto.Marshal,
	}
}

// NOTE: Avoid duplicate messages from the same peer should be handled in the caller
func (t *EchoMsgMain) AddMessage(senderId string, msg types.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	eMsg, ok := msg.(EchoMessage)
	if !ok {
		return ErrNotEchoMsg
	}

	hash, err := t.echoHash(eMsg)
	if err != nil {
		return err
	}
	if hash == nil {
		return t.MessageMain.AddMessage(senderId, msg)
	}

	// Init echo messages
	msgType := msg.GetMessageType()
	echoMsg, ok := t.echoMsgs[msgType]
	if !ok {
		echoMsg = make(map[string]*echoMessage)
		t.echoMsgs[msgType] = echoMsg
	}
	msgId := msg.GetId()
	// Broadcast to other peers for the first message
	m, ok := echoMsg[msgId]
	if !ok {
		for _, id := range t.pm.PeerIDs() {
			if msgId != id {
				go t.pm.MustSend(id, eMsg.GetEchoMessage())
			}
		}
		echoMsg[msgId] = &echoMessage{
			hash:   hash,
			msgMap: make(map[string]struct{}),
		}
		m = echoMsg[msgId]
	} else if !bytes.Equal(m.hash, hash) {
		return ErrDifferentHash
	}

	// If it's an original message
	if senderId == msgId && m.originalMsg == nil {
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

func (t *EchoMsgMain) echoHash(m EchoMessage) ([]byte, error) {
	echoMsg := m.GetEchoMessage()
	if echoMsg == nil {
		return nil, nil
	}
	// NOTE: there's an issue if there's a map field in the message
	// https://developers.google.com/protocol-buffers/docs/encoding#implications
	// Deterministic serialization only guarantees the same byte output for a particular binary.
	bs, err := t.marshalFunc(echoMsg.(proto.Message))
	if err != nil {
		return nil, err
	}
	got := blake2b.Sum256(bs)
	return got[:], nil
}
