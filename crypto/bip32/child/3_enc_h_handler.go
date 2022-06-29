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
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"golang.org/x/crypto/blake2b"
)

type encH struct {
	*otSendResponse
}

func newEncH(oh *otSendResponse) *encH {
	return &encH{
		otSendResponse: oh,
	}
}
func (s *encH) MessageType() types.MessageType {
	return types.MessageType(Type_EncH)
}

func (s *encH) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *encH) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *encH) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetEncH()
	cipherh2, err := peer.pubkey.Encrypt(s.h2)
	if err != nil {
		logger.Warn("Failed to encrypt h", "err", err)
		return err
	}
	result, err := peer.pubkey.Add(body.EncH, cipherh2)
	if err != nil {
		logger.Warn("Failed to add encH and cipherh2", "err", err)
		return err
	}

	r, err := utils.RandomInt(peer.pubkeyN)
	if err != nil {
		logger.Warn("Failed to random r", "err", err)
		return err
	}
	result, err = peer.pubkey.MulConst(result, r)
	if err != nil {
		logger.Warn("Failed to mul const r", "err", err)
		return err
	}

	ps, err := utils.RandomInt(peer.pubkeyN)
	if err != nil {
		logger.Warn("Failed to random s", "err", err)
		return err
	}
	sBytesCipher, err := peer.pubkey.Encrypt(ps.Bytes())
	if err != nil {
		logger.Warn("Failed to mul const r", "err", err)
		return err
	}
	result, err = peer.pubkey.Add(result, sBytesCipher)
	if err != nil {
		logger.Warn("Failed to add result and sBytesCipher", "err", err)
		return err
	}

	sh2 := append(append(ps.Bytes(), uint8(',')), s.h2...)
	hashResult := blake2b.Sum256(sh2)
	s.peerManager.MustSend(id, &Message{
		Type: Type_Sh2Hash,
		Id:   s.selfId,
		Body: &Message_Sh2Hash{
			Sh2Hash: &BodySh2Hash{
				Result:  result,
				Sh2Hash: hashResult[:],
			},
		},
	})
	return peer.AddMessage(msg)
}

func (s *encH) Finalize(logger log.Logger) (types.Handler, error) {
	return newSh2Hash(s), nil
}
