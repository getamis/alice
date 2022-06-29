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
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type resultHandler struct {
	*decommitmentHandler

	share  *big.Int
	shareG *pt.ECPoint
}

func newResultHandler(oh *decommitmentHandler) *resultHandler {
	return &resultHandler{
		decommitmentHandler: oh,
	}
}
func (s *resultHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Result)
}

func (s *resultHandler) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *resultHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *resultHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetResult()
	// Feldman commitment
	p, err := peer.randomChooseG.Add(peer.randomSeedG.Neg())
	if err != nil {
		logger.Warn("Failed to add", "err", err)
		return err
	}
	err = body.GetResult().VerifyByPoints(curve, []*pt.ECPoint{
		p,
		peer.aG,
	}, s.bk, 1)
	if err != nil {
		logger.Warn("Failed to verify", "err", err)
		return err
	}
	s.share = new(big.Int).Add(s.poly.Evaluate(s.bk.GetX()), new(big.Int).SetBytes(body.GetResult().Evaluation))
	s.share = s.share.Mul(s.share, big2Inver)
	s.share = s.share.Mod(s.share, secp256k1N)
	shareGMsg, err := zkproof.NewBaseSchorrMessage(curve, s.share)
	if err != nil {
		logger.Warn("Failed to get share G message", "err", err)
		return err
	}
	s.shareG, _ = shareGMsg.V.ToPoint()
	s.peerManager.MustSend(id, &Message{
		Type: Type_Verify,
		Id:   s.selfId,
		Body: &Message_Verify{
			Verify: &BodyVerify{
				ShareGProofMsg: shareGMsg,
			},
		},
	})

	return peer.AddMessage(msg)
}

func (s *resultHandler) Finalize(logger log.Logger) (types.Handler, error) {
	return newVerifyHandler(s), nil
}
