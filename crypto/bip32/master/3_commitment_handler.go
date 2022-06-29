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

package master

import (
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type commitmentHandler struct {
	*otSendResponse

	a  *big.Int
	aG *pt.ECPoint
}

func newCommitmentHandler(oh *otSendResponse) *commitmentHandler {
	return &commitmentHandler{
		otSendResponse: oh,
	}
}
func (s *commitmentHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Commitment)
}

func (s *commitmentHandler) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *commitmentHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *commitmentHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	var err error
	s.a, err = utils.RandomInt(secp256k1N)
	if err != nil {
		logger.Warn("Failed to create a1", "err", err)
		return err
	}
	s.aG = pt.ScalarBaseMult(curve, s.a)
	aM, err := s.aG.ToEcPointMessage()
	if err != nil {
		logger.Warn("Failed to create a1 message", "err", err)
		return err
	}

	s.peerManager.MustSend(id, &Message{
		Type: Type_Decommitment,
		Id:   s.selfId,
		Body: &Message_Decommitment{
			Decommitment: &BodyDecommitment{
				RandomChooseDeommitment: s.randomChooseGCommiter.GetDecommitmentMessage(),
				RandomSeedDecommitment:  s.randomSeedGCommiter.GetDecommitmentMessage(),
				AG:                      aM,
			},
		},
	})
	return peer.AddMessage(msg)
}

func (s *commitmentHandler) Finalize(logger log.Logger) (types.Handler, error) {
	return newDecommitmentHandler(s), nil
}
