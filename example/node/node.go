// Copyright © 2023 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"io"
	"reflect"

	"github.com/getamis/sirius/log"
	"github.com/libp2p/go-libp2p-core/network"
	"google.golang.org/protobuf/proto"

	"github.com/getamis/alice/types"
)

type node[M Message, R any] struct {
	backend  Backend[M, R]
	listener Listener
	pm       types.PeerManager
}

func New[M Message, R any](backend Backend[M, R], l Listener, pm types.PeerManager) *node[M, R] {
	return &node[M, R]{
		backend:  backend,
		listener: l,
		pm:       pm,
	}
}

func (n *node[M, R]) Handle(s network.Stream) {
	var data M
	buf, err := io.ReadAll(s)
	if err != nil {
		log.Warn("Cannot read data from stream", "err", err)
		return
	}
	s.Close()

	msgType := reflect.TypeOf(data).Elem()
	data = reflect.New(msgType).Interface().(M)

	// unmarshal it
	err = proto.Unmarshal(buf, data)
	if err != nil {
		log.Error("Cannot unmarshal data", "err", err)
		return
	}

	// log.Info("Received request", "from", s.Conn().RemotePeer())
	err = n.backend.AddMessage(data.GetId(), data)
	if err != nil {
		log.Warn("Cannot add message to DKG", "err", err)
		return
	}
}

func (n *node[M, R]) Process() (r R, _ error) {
	// 1. Start the process.
	n.backend.Start()
	defer n.backend.Stop()

	if err := <-n.listener.Done(); err != nil {
		return r, err
	}

	// 2. Wait for the result or errors
	return n.backend.GetResult()
}
