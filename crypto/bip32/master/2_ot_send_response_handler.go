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

	"github.com/getamis/alice/crypto/circuit"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type otSendResponse struct {
	*otReceiver

	// Results
	chiancode    []byte
	randomChoose *big.Int
}

func newOtSendResponse(oh *otReceiver) *otSendResponse {
	return &otSendResponse{
		otReceiver: oh,
	}
}
func (s *otSendResponse) MessageType() types.MessageType {
	return types.MessageType(Type_OtSendResponse)
}

func (s *otSendResponse) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *otSendResponse) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *otSendResponse) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetOtSendResponse()
	ownResult, err := s.otExtReceiver.GetOTFinalResult(body.GetOtExtSendResponseMsg())
	if err != nil {
		log.Warn("Failed to find result", "err", err)
		return err
	}
	initMessage := getMessage(peer.GetMessage(types.MessageType(Type_Intial))).GetInitial()
	cir := s.parseResultFunc(initMessage, ownResult)

	garMsg := initMessage.GarcirMsg
	evaluation, err := s.garcircuit.EvaluateGarbleCircuit(garMsg, cir)
	if err != nil {
		log.Warn("Failed to evaluate garble circuit", "err", err)
		return err
	}

	byteSlice, err := utils.BitsToBytes(utils.ReverseByte(circuit.Decrypt(garMsg.GetD(), evaluation)))
	if err != nil {
		log.Warn("Failed to convert from bits to bytes", "err", err)
		return err
	}
	s.chiancode = byteSlice[0:32]
	s.randomChoose = new(big.Int).SetBytes(byteSlice[64:])
	return peer.AddMessage(msg)
}

func (s *otSendResponse) Finalize(logger log.Logger) (types.Handler, error) {
	return nil, nil
}
