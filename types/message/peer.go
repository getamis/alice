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
	"errors"

	"github.com/getamis/alice/types"
)

var (
	ErrDupMessage = errors.New("duplicate message")
	ErrNotYours   = errors.New("not yours")
)

type Peer struct {
	Id       string
	Messages map[types.MessageType]types.Message
}

func NewPeer(id string) *Peer {
	return &Peer{
		Id:       id,
		Messages: make(map[types.MessageType]types.Message),
	}
}

func (p *Peer) AddMessage(msg types.Message) error {
	if p.Id != msg.GetId() {
		return ErrNotYours
	}
	t := msg.GetMessageType()
	_, ok := p.Messages[t]
	if ok {
		return ErrDupMessage
	}
	p.Messages[t] = msg
	return nil
}

func (p *Peer) GetMessage(t types.MessageType) types.Message {
	return p.Messages[t]
}
