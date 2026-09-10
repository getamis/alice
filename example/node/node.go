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
	"github.com/libp2p/go-libp2p/core/network"
	"google.golang.org/protobuf/proto"

	"github.com/getamis/alice/types"
)

type node[M Message, R any] struct {
	backend  Backend[M, R]
	listener Listener
	pm       types.PeerManager
}

// transportPeerMapper resolves an authenticated transport-layer peer ID to
// the logical session ID it belongs to.
type transportPeerMapper interface {
	SessionIDForTransportPeer(transportID string) (string, bool)
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

	// Resolve the sender from the authenticated transport connection instead
	// of trusting the self-declared Id inside the message payload.
	mapper, ok := n.pm.(transportPeerMapper)
	if !ok {
		log.Warn("Peer manager does not support sender authentication")
		return
	}
	senderId, ok := mapper.SessionIDForTransportPeer(s.Conn().RemotePeer().String())
	if !ok {
		log.Warn("Cannot resolve sender for transport peer", "peer", s.Conn().RemotePeer())
		return
	}

	// log.Info("Received request", "from", s.Conn().RemotePeer())
	err = n.backend.AddMessage(senderId, data)
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
