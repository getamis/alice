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
	"sync/atomic"

	"github.com/getamis/sirius/log"
)

// PeerManager defines the peer interface
//
//go:generate mockery --name=PeerManager
type PeerManager interface {
	NumPeers() uint32
	PeerIDs() []string
	SelfID() string
	MustSend(id string, msg interface{})
}

// Handler defines the message handler
//
//go:generate mockery --name=Handler
type Handler interface {
	// MessageType return the message type which the handler want to collect
	MessageType() MessageType
	// GetRequiredMessageCount gets required message count in this round
	GetRequiredMessageCount() uint32
	// IsHandled checks if the id's message is handled before
	IsHandled(logger log.Logger, id string) bool
	// HandleMessage handles the message
	HandleMessage(logger log.Logger, msg Message) error
	// Finalize finalizes the result based on the collected messages and return the next handler.
	// If next handler is nil, it means it's the end of the main process
	Finalize(logger log.Logger) (Handler, error)
}

type HandlerWrapper struct {
	wrapped atomic.Value
}

type HandlerWrapped struct {
	handler Handler
}

func NewHandlerWrapper(h Handler) *HandlerWrapper {
	wrapper := &HandlerWrapper{}
	wrapped := &HandlerWrapped{handler: h}
	wrapper.wrapped.Store(wrapped)

	return wrapper
}

func (h *HandlerWrapper) Handler() Handler {
	return h.wrapped.Load().(*HandlerWrapped).handler
}

func (h *HandlerWrapper) SetHandler(handler Handler) {
	h.wrapped.Store(&HandlerWrapped{handler: handler})
}

// MessageType defines the message state
type MessageType int32

// Message defines the message interface
//
//go:generate mockery --name=Message
type Message interface {
	// GetId returns the message id
	GetId() string
	// GetMessageType returns the message type
	GetMessageType() MessageType
	// IsValid checks if message is valid or not
	IsValid() bool
}

// MessageMain defines the message main interface
//
//go:generate mockery --name=MessageMain
type MessageMain interface {
	AddMessage(senderId string, msg Message) error
	GetHandler() Handler
	GetState() MainState
	Start()
	Stop()
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

//go:generate mockery --name=StateChangedListener
type StateChangedListener interface {
	OnStateChanged(oldState MainState, newState MainState)
}
