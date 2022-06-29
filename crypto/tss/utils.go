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

package tss

import (
	"errors"
	"fmt"

	"github.com/getamis/alice/types"
)

var (
	ErrInvalidMsg                = errors.New("invalid message")
	ErrNotReady                  = errors.New("not ready")
	ErrPeerNotFound              = errors.New("peer message not found")
	ErrNotEnoughBKs              = errors.New("not enough Birkhoff coefficient")
	ErrSelfBKNotFound            = errors.New("self Birkhoff coefficient not found")
	ErrInvalidBK                 = errors.New("invalid Birkhoff coefficient")
	ErrInconsistentThreshold     = errors.New("inconsistent threshold")
	ErrInconsistentPeerNumAndBks = errors.New("inconsistent peer num and bks")
	ErrInconsistentPubKey        = errors.New("inconsistent public key")
)

// ------------
// Below funcs are for testing
func GetTestID(id int) string {
	return fmt.Sprintf("id-%d", id)
}

func GetTestPeers(id int, lens int) []string {
	var peers []string
	for i := 0; i < lens; i++ {
		if i == id {
			continue
		}
		peers = append(peers, GetTestID(i))
	}
	return peers
}

func GetTestPeersByArray(id int, ids []int) []string {
	var peers []string
	for _, peerID := range ids {
		if peerID == id {
			continue
		}
		peers = append(peers, GetTestID(peerID))
	}
	return peers
}

type TestPeerManager struct {
	id       string
	peers    []string
	msgMains map[string]types.MessageMain
}

func NewTestPeerManager(id int, lens int) *TestPeerManager {
	return &TestPeerManager{
		id:       GetTestID(id),
		peers:    GetTestPeers(id, lens),
		msgMains: make(map[string]types.MessageMain),
	}
}

func NewTestPeerManagerWithPeers(id int, peers []string) *TestPeerManager {
	return &TestPeerManager{
		id:       GetTestID(id),
		peers:    peers,
		msgMains: make(map[string]types.MessageMain),
	}
}

func (p *TestPeerManager) Set(msgMains map[string]types.MessageMain) {
	p.msgMains = msgMains
}

func (p *TestPeerManager) NumPeers() uint32 {
	return uint32(len(p.peers))
}

func (p *TestPeerManager) SelfID() string {
	return p.id
}

func (p *TestPeerManager) PeerIDs() []string {
	return p.peers
}

// Only send if the msg main exists
func (p *TestPeerManager) MustSend(id string, message interface{}) {
	d, ok := p.msgMains[id]
	if !ok {
		return
	}
	msg := message.(types.Message)
	d.AddMessage(msg)
}
