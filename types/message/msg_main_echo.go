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
	"slices"
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
	// GetEchoMessage() returns the reduced, public-fields-only message used to
	// cross-check consistency via the echo protocol, or nil if this message
	// type isn't echo-tracked.
	GetEchoMessage() types.Message
}

var (
	ErrNotEchoMsg    = errors.New("not a echo message")
	ErrDifferentHash = errors.New("different hash")
	ErrInvalidRelay  = errors.New("invalid echo relay")
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
	hash []byte
	// hashConfirmed is true once the authenticated origin has set the hash;
	// before that it only reflects an unconfirmed relay and may be corrected.
	hashConfirmed bool
	votes         map[string]struct{}
	originalMsg   types.Message
	relayed       bool
}

func NewEchoMsgMain(next types.MessageMain, pm types.PeerManager) *EchoMsgMain {
	return &EchoMsgMain{
		MessageMain: next,
		logger:      log.New(),
		pm:          pm,
		echoMsgs:    make(map[types.MessageType]map[string]*echoMessage),
		marshalFunc: proto.MarshalOptions{Deterministic: true}.Marshal,
	}
}

func (t *EchoMsgMain) AddMessage(senderId string, msg types.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	eMsg, ok := msg.(EchoMessage)
	if !ok {
		return ErrNotEchoMsg
	}

	// ensure both the sender and the message ID are participants in the protocol
	msgId := msg.GetId()
	if !t.isParticipant(senderId) || !t.isParticipant(msgId) {
		return ErrInvalidRelay
	}

	// senderId is authenticated by the transport layer (see example/node), so
	// only the genuine origin can ever produce senderId == msgId; anyone else
	// sending on msgId's behalf is necessarily relaying.
	isOriginal := senderId == msgId

	canonical := eMsg.GetEchoMessage()
	if canonical == nil {
		if !isOriginal {
			return ErrInvalidRelay
		}
		return t.MessageMain.AddMessage(senderId, msg)
	}
	if !isOriginal && !proto.Equal(eMsg, canonical.(proto.Message)) {
		// a relay must only ever carry the reduced, public-only content
		return ErrInvalidRelay
	}

	hash, err := t.echoHash(canonical)
	if err != nil {
		return err
	}

	msgType := msg.GetMessageType()
	echoMsgs, ok := t.echoMsgs[msgType]
	if !ok {
		echoMsgs = make(map[string]*echoMessage)
		t.echoMsgs[msgType] = echoMsgs
	}
	m, ok := echoMsgs[msgId]
	if !ok {
		m = &echoMessage{hash: hash, votes: make(map[string]struct{})}
		echoMsgs[msgId] = m
	} else if !bytes.Equal(m.hash, hash) {
		if !isOriginal || m.hashConfirmed {
			return ErrDifferentHash
		}
		// The hash so far only came from an unconfirmed relay; the
		// authenticated origin always wins and corrects it. Votes collected
		// against the wrong hash no longer apply.
		m.hash = hash
		m.votes = make(map[string]struct{})
	}

	m.votes[senderId] = struct{}{}
	if isOriginal {
		m.hashConfirmed = true
		m.originalMsg = msg
		m.votes[t.pm.SelfID()] = struct{}{}
		if !m.relayed {
			for _, id := range t.pm.PeerIDs() {
				if id == msgId {
					continue
				}
				go t.pm.MustSend(id, canonical)
			}
			m.relayed = true
		}
	}

	if m.originalMsg == nil || len(m.votes) != len(t.pm.PeerIDs())+1 {
		return nil
	}
	delete(echoMsgs, msgId)
	return t.MessageMain.AddMessage(m.originalMsg.GetId(), m.originalMsg)
}

func (t *EchoMsgMain) isParticipant(id string) bool {
	if id == t.pm.SelfID() {
		return true
	}
	return slices.Contains(t.pm.PeerIDs(), id)
}

func (t *EchoMsgMain) echoHash(echoMsg types.Message) ([]byte, error) {
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
