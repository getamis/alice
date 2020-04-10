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

package types

import (
	"github.com/getamis/sirius/log"
	"github.com/golang/protobuf/proto"
)

// PeerManager defines the peer interface
//go:generate mockery -name=PeerManager
type PeerManager interface {
	NumPeers() uint32
	SelfID() string
	MustSend(id string, msg proto.Message)
}

// Handler defines the message handler
//go:generate mockery -name=Handler
type Handler interface {
	// MessageType return the message type which the handler want to collect
	MessageType() MessageType
	// IsHandled checks if the id's message is handled before
	IsHandled(logger log.Logger, id string) bool
	// HandleMessage handles the message
	HandleMessage(logger log.Logger, msg Message) error
	// Finalize finalizes the result based on the collected messages and return the next handler.
	// If next handler is nil, it means it's the end of the main process
	Finalize(logger log.Logger) (Handler, error)
}

// MessageType defines the message state
type MessageType int32

// Message defines the message interface
//go:generate mockery -name=Message
type Message interface {
	// GetId returns the message id
	GetId() string
	// GetMessageType returns the message type
	GetMessageType() MessageType
	// IsValid checks if message is valid or not
	IsValid() bool
}

// MainState defines the msg main state
type MainState uint32

const (
	// StateInit is the state if the process is just created.
	StateInit MainState = 0
	// StateDone is the state if the process is done.
	StateDone MainState = 10
	// StateFailed is the state if the process is failed
	StateFailed MainState = 20
)

func (m MainState) String() string {
	switch m {
	case StateInit:
		return "Init"
	case StateDone:
		return "Done"
	case StateFailed:
		return "Failed"
	}
	return "Unknown"
}

//go:generate mockery -name=StateChangedListener
type StateChangedListener interface {
	OnStateChanged(oldState MainState, newState MainState)
}
