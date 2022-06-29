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
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/circuit"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"github.com/minio/blake2b-simd"
)

var (
	// ErrSliceLength is returned if two slices are different.
	ErrSliceLength = errors.New("two slices are different")
	// ErrVerifyFailure is returned the verify failures.
	ErrVerifyFailure = errors.New("the verify failures")
)

type otSendResponse struct {
	*otReceiver

	result []byte
	h2     []byte
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
	ownResult, err := peer.otExtReceiver.GetOTFinalResult(body.GetOtExtSendResponseMsg())
	if err != nil {
		logger.Warn("Failed to find result", "err", err)
		return err
	}
	initMessage := getMessage(peer.GetMessage(types.MessageType(Type_Initial))).GetInitial()
	cir := s.parseResultFunc(initMessage, ownResult)

	garMsg := initMessage.GarcirMsg
	evaluation, err := s.garcircuit.EvaluateGarbleCircuit(garMsg, cir)
	if err != nil {
		logger.Warn("Failed to evaluate garble circuit", "err", err)
		return err
	}

	s.result, err = utils.BitsToBytes(utils.ReverseByte(circuit.Decrypt(garMsg.GetD(), evaluation)))
	if err != nil {
		logger.Warn("Failed to convert from bits to bytes", "err", err)
		return err
	}
	// Compute h2
	wv, err := getWv(s.garcircuit.GetOutputWire(), garMsg.HOutputWire0, garMsg.HOutputWire1, evaluation)
	if err != nil {
		logger.Warn("Failed to get wv", "err", err)
		return err
	}
	s.h2 = s.hashFunc(s.sid, wv, evaluation)
	minush := new(big.Int).SetBytes(s.h2)
	minush = minush.Neg(minush)
	minush.Mod(minush, s.homoKey.GetN())
	encH, err := s.homoKey.Encrypt(minush.Bytes())
	if err != nil {
		logger.Warn("Failed to encrypt h", "err", err)
		return err
	}
	s.peerManager.MustSend(id, &Message{
		Type: Type_EncH,
		Id:   s.selfId,
		Body: &Message_EncH{
			EncH: &BodyEncH{
				EncH: encH,
			},
		},
	})

	return peer.AddMessage(msg)
}

func (s *otSendResponse) Finalize(logger log.Logger) (types.Handler, error) {
	return newEncH(s), nil
}

func getWv(ownOutputWire [][][]byte, hashW0 [][]byte, hashW1 [][]byte, evaluateResult [][]byte) ([][]byte, error) {
	if len(hashW0) != len(hashW1) {
		return nil, ErrSliceLength
	}
	if len(hashW0) != len(evaluateResult) {
		return nil, ErrSliceLength
	}
	result := make([][]byte, len(evaluateResult))
	for i := 0; i < len(result); i++ {
		tempHash := blake2b.Sum256(evaluateResult[i])
		if subtle.ConstantTimeCompare(tempHash[:], hashW0[i]) == 1 {
			result[i] = ownOutputWire[i][0]
			continue
		}
		if subtle.ConstantTimeCompare(tempHash[:], hashW1[i]) == 1 {
			result[i] = ownOutputWire[i][1]
			continue
		}
		return nil, ErrVerifyFailure
	}
	return result, nil
}
