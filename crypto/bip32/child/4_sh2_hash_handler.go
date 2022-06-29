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

package child

import (
	"crypto/subtle"

	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"golang.org/x/crypto/blake2b"
)

type sh2Hash struct {
	*encH

	childShare *childShare
}

func newSh2Hash(oh *encH) *sh2Hash {
	return &sh2Hash{
		encH: oh,
	}
}
func (s *sh2Hash) MessageType() types.MessageType {
	return types.MessageType(Type_Sh2Hash)
}

func (s *sh2Hash) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *sh2Hash) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *sh2Hash) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetSh2Hash()
	plaintext, err := s.homoKey.Decrypt(body.Result)
	if err != nil {
		logger.Warn("Failed to decrypt", "err", err)
		return ErrVerifyFailure
	}
	hatsh := append(append(plaintext, uint8(',')), s.h2...)
	hashResult := blake2b.Sum256(hatsh)
	if subtle.ConstantTimeCompare(hashResult[:], body.Sh2Hash) != 1 {
		logger.Warn("Inconsistent hash")
		return ErrVerifyFailure
	}
	s.childShare, err = s.sm.ComputeHardenedChildShare(s.childIndex, s.result)
	if err != nil {
		logger.Warn("Failed to compute child share", "err", err)
		return ErrVerifyFailure
	}
	return peer.AddMessage(msg)
}

func (s *sh2Hash) Finalize(logger log.Logger) (types.Handler, error) {
	return nil, nil
}
