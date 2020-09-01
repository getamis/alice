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
	"context"
	"errors"
	"sync"

	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/sirius/log"
)

var (
	ErrInvalidStateTransition = errors.New("invalid state transition")
	ErrDupMsg                 = errors.New("duplicate message")
)

type MsgMain struct {
	logger         log.Logger
	peerNum        uint32
	msgChs         *MsgChans
	state          types.MainState
	currentHandler types.Handler
	listener       types.StateChangedListener
	finalError     error

	lock   sync.RWMutex
	cancel context.CancelFunc
}

func NewMsgMain(id string, peerNum uint32, listener types.StateChangedListener, initHandler types.Handler, msgTypes ...types.MessageType) *MsgMain {
	return &MsgMain{
		logger:         log.New("self", id),
		peerNum:        peerNum,
		msgChs:         NewMsgChans(peerNum, msgTypes...),
		state:          types.StateInit,
		currentHandler: initHandler,
		listener:       listener,
	}
}

func (t *MsgMain) Start() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	//nolint:errcheck
	go t.messageLoop(ctx)
	t.cancel = cancel
}

func (t *MsgMain) Stop() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.cancel == nil {
		return
	}
	t.cancel()
	t.cancel = nil
}

func (t *MsgMain) AddMessage(msg types.Message) error {
	return t.msgChs.Push(msg)
}

func (t *MsgMain) GetHandler() types.Handler {
	return t.currentHandler
}

func (t *MsgMain) GetState() types.MainState {
	return t.state
}

func (t *MsgMain) GetFinalError() error {
	return t.finalError
}

func (t *MsgMain) messageLoop(ctx context.Context) (err error) {
	defer func() {
		if err == nil {
			_ = t.setState(types.StateDone, nil)
		} else {
			_ = t.setState(types.StateFailed, err)
		}
		t.Stop()
	}()

	handler := t.currentHandler
	msgType := handler.MessageType()
	msgCount := uint32(0)
	for {
		// 1. Pop messages
		// 2. Check if the message is handled before
		// 3. Handle the message
		// 4. Check if we collect enough messages
		// 5. If yes, finalize the handler. Otherwise, wait for the next message
		msg, err := t.msgChs.Pop(ctx, msgType)
		if err != nil {
			t.logger.Warn("Failed to pop message", "err", err)
			return err
		}
		id := msg.GetId()
		logger := t.logger.New("msgType", msgType, "fromId", id)
		if handler.IsHandled(logger, id) {
			logger.Warn("The message is handled before")
			return ErrDupMsg
		}

		err = handler.HandleMessage(logger, msg)
		if err != nil {
			logger.Warn("Failed to save message", "err", err)
			return err
		}

		msgCount++
		if msgCount < handler.GetRequiredMessageCount() {
			continue
		}

		nextHandler, err := handler.Finalize(logger)
		if err != nil {
			logger.Warn("Failed to go to next handler", "err", err)
			return err
		}
		// if nextHandler is nil, it means we got the final result
		if nextHandler == nil {
			return nil
		}
		t.currentHandler = nextHandler
		handler = t.currentHandler
		newType := handler.MessageType()
		logger.Info("Change handler", "oldType", msgType, "newType", newType)
		msgType = newType
		msgCount = uint32(0)
	}
}

func (t *MsgMain) setState(newState types.MainState, err error) error {
	if t.isInFinalState() {
		t.logger.Warn("Invalid state transition", "old", t.state, "new", newState)
		return ErrInvalidStateTransition
	}

	t.logger.Info("State changed", "old", t.state, "new", newState)
	oldState := t.state
	t.state = newState
	t.finalError = err
	t.listener.OnStateChanged(oldState, newState)
	return nil
}

func (t *MsgMain) isInFinalState() bool {
	return t.state == types.StateFailed || t.state == types.StateDone
}
