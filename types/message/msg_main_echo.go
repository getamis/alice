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
//go:generate go run github.com/vektra/mockery/v2 --name=EchoMessage
type EchoMessage interface {
	proto.Message
	types.Message
	// GetEchoMessage() return the message to broadcast in echo protocol
	GetEchoMessage() types.Message
}

type EchoRelayMessage interface {
	IsEchoRelay() bool
}

var (
	ErrNotEchoMsg    = errors.New("not a echo message")
	ErrDifferentHash = errors.New("different hash")
	ErrInvalidRelay  = errors.New("invalid echo relay")
)

const completedEchoLimit = 1024

type EchoMsgMain struct {
	types.MessageMain

	logger log.Logger
	pm     types.PeerManager
	mu     sync.Mutex
	// keep echo msgs
	// map[message type][the message id]
	echoMsgs           map[types.MessageType]map[string]*echoMessage
	completedEchoMsgs  map[types.MessageType]map[string][]byte
	completedEchoOrder []echoMessageKey

	marshalFunc func(m proto.Message) ([]byte, error)
}

type echoMessage struct {
	hash        []byte
	votes       map[string]struct{}
	originalMsg types.Message
	relayed     bool
}

type echoMessageKey struct {
	msgType types.MessageType
	msgID   string
}

func NewEchoMsgMain(next types.MessageMain, pm types.PeerManager) *EchoMsgMain {
	msgs := make(map[types.MessageType]map[string]*echoMessage)
	return &EchoMsgMain{
		MessageMain:       next,
		logger:            log.New(),
		pm:                pm,
		echoMsgs:          msgs,
		completedEchoMsgs: make(map[types.MessageType]map[string][]byte),
		marshalFunc:       proto.MarshalOptions{Deterministic: true}.Marshal,
	}
}

func (t *EchoMsgMain) AddMessage(senderId string, msg types.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	eMsg, ok := msg.(EchoMessage)
	if !ok {
		return ErrNotEchoMsg
	}
	if !t.isParticipant(senderId) || !t.isParticipant(msg.GetId()) {
		return ErrInvalidRelay
	}

	if relay, ok := eMsg.(EchoRelayMessage); ok && relay.IsEchoRelay() {
		canonical := eMsg.GetEchoMessage()
		if canonical == nil || !proto.Equal(eMsg, canonical.(proto.Message)) {
			return ErrInvalidRelay
		}
	} else if senderId != msg.GetId() {
		return ErrBadMsg
	}

	hash, err := t.echoHash(eMsg)
	if err != nil {
		return err
	}
	if hash == nil {
		if relay, ok := eMsg.(EchoRelayMessage); ok && relay.IsEchoRelay() {
			return ErrInvalidRelay
		}
		return t.MessageMain.AddMessage(senderId, msg)
	}

	msgType := msg.GetMessageType()
	msgId := msg.GetId()
	if completedHash, ok := t.completedHash(msgType, msgId); ok {
		if !bytes.Equal(completedHash, hash) {
			return ErrDifferentHash
		}
		return nil
	}
	echoMsg, ok := t.echoMsgs[msgType]
	if !ok {
		echoMsg = make(map[string]*echoMessage)
		t.echoMsgs[msgType] = echoMsg
	}
	m, ok := echoMsg[msgId]
	if !ok {
		echoMsg[msgId] = &echoMessage{
			hash:  hash,
			votes: make(map[string]struct{}),
		}
		m = echoMsg[msgId]
	} else if !bytes.Equal(m.hash, hash) {
		return ErrDifferentHash
	}

	if relay, ok := eMsg.(EchoRelayMessage); ok && relay.IsEchoRelay() {
		m.votes[senderId] = struct{}{}
		return t.deliverEchoMessage(msgType, msgId, m)
	}

	m.originalMsg = msg
	m.votes[senderId] = struct{}{}
	m.votes[t.pm.SelfID()] = struct{}{}
	if !m.relayed {
		for _, id := range t.pm.PeerIDs() {
			go t.pm.MustSend(id, eMsg.GetEchoMessage())
		}
		m.relayed = true
	}
	return t.deliverEchoMessage(msgType, msgId, m)
}

func (t *EchoMsgMain) deliverEchoMessage(msgType types.MessageType, msgId string, m *echoMessage) error {
	if m.originalMsg == nil || len(m.votes) != len(t.pm.PeerIDs())+1 {
		return nil
	}
	delete(t.echoMsgs[msgType], msgId)
	t.addCompletedHash(msgType, msgId, m.hash)
	return t.MessageMain.AddMessage(m.originalMsg.GetId(), m.originalMsg)
}

func (t *EchoMsgMain) isParticipant(id string) bool {
	if id == t.pm.SelfID() {
		return true
	}
	for _, peerID := range t.pm.PeerIDs() {
		if id == peerID {
			return true
		}
	}
	return false
}

func (t *EchoMsgMain) completedHash(msgType types.MessageType, msgID string) ([]byte, bool) {
	byID, ok := t.completedEchoMsgs[msgType]
	if !ok {
		return nil, false
	}
	hash, ok := byID[msgID]
	return hash, ok
}

func (t *EchoMsgMain) addCompletedHash(msgType types.MessageType, msgID string, hash []byte) {
	if len(t.completedEchoOrder) == completedEchoLimit {
		oldest := t.completedEchoOrder[0]
		delete(t.completedEchoMsgs[oldest.msgType], oldest.msgID)
		t.completedEchoOrder = t.completedEchoOrder[1:]
	}
	byID, ok := t.completedEchoMsgs[msgType]
	if !ok {
		byID = make(map[string][]byte)
		t.completedEchoMsgs[msgType] = byID
	}
	byID[msgID] = append([]byte(nil), hash...)
	t.completedEchoOrder = append(t.completedEchoOrder, echoMessageKey{msgType: msgType, msgID: msgID})
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
