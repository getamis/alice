// Copyright © 2021 AMIS Technologies
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

package verifier

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

var (
	ErrNotFeldmanRelation = errors.New("not a Feldman relation")
)

type serverHandler3 struct {
	*serverHandler2

	newShare *big.Int
}

func newServerHandler3(s *serverHandler2) (*serverHandler3, error) {
	return &serverHandler3{
		serverHandler2: s,
	}, nil
}

func (p *serverHandler3) MessageType() types.MessageType {
	return types.MessageType(Type_MsgUser3)
}

func (p *serverHandler3) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *serverHandler3) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	user3 := msg.GetUser3()
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}

	// Schnorr verify
	err := p.shareGVerifier.Verify(user3.ShareGProver3)
	if err != nil {
		logger.Debug("Failed to verify (share)", "err", err)
		return err
	}

	return peer.AddMessage(msg)
}

func (p *serverHandler3) Finalize(logger log.Logger) (types.Handler, error) {
	return nil, nil
}
