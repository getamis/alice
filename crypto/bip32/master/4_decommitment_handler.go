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
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	ErrIdentityPublicKey   = errors.New("identity public key")
	ErrInconsistentResults = errors.New("inconsistent results")
)

type decommitmentHandler struct {
	*commitmentHandler

	poly                *polynomial.Polynomial
	feldmanCommitmenter *commitment.FeldmanCommitmenter
	publicKey           *pt.ECPoint
}

func newDecommitmentHandler(oh *commitmentHandler) *decommitmentHandler {
	return &decommitmentHandler{
		commitmentHandler: oh,
	}
}
func (s *decommitmentHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Decommitment)
}

func (s *decommitmentHandler) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *decommitmentHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *decommitmentHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	// Check decommit message
	decommitmentMessage := msg.GetDecommitment()
	commitmentMessage := getMessage(peer.GetMessage(types.MessageType(Type_Commitment))).GetCommitment()
	var err error
	peer.randomChooseG, err = commitment.GetPointFromHashCommitment(commitmentMessage.GetRandomChooseCommitment(), decommitmentMessage.GetRandomChooseDeommitment())
	if err != nil {
		logger.Warn("Failed to decommit random choose message", "err", err)
		return err
	}
	peer.randomSeedG, err = commitment.GetPointFromHashCommitment(commitmentMessage.GetRandomSeedCommitment(), decommitmentMessage.GetRandomSeedDecommitment())
	if err != nil {
		logger.Warn("Failed to decommit random seed message", "err", err)
		return err
	}
	peer.aG, err = decommitmentMessage.GetAG().ToPoint()
	if err != nil {
		logger.Warn("Failed to get ag", "err", err)
		return err
	}

	// Verify (s+b)*G - b*G == (s+a)*G - a*G
	s.publicKey, err = s.randomChooseG.Add(peer.randomSeedG.Neg())
	if err != nil {
		logger.Warn("Failed to add randomChooseG and randomSeedG", "err", err)
		return err
	}
	if s.publicKey.IsIdentity() {
		logger.Warn("Identity public key")
		return ErrIdentityPublicKey
	}
	got2, err := peer.randomChooseG.Add(s.randomSeedG.Neg())
	if err != nil {
		logger.Warn("Failed to add self randomChooseG and randomSeedG", "err", err)
		return err
	}
	if !s.publicKey.Equal(got2) {
		logger.Warn("Inconsistent results")
		return ErrInconsistentResults
	}

	s.poly, err = polynomial.NewPolynomial(secp256k1N, []*big.Int{
		new(big.Int).Sub(s.randomChoose, s.randomSeed),
		s.a,
	})
	if err != nil {
		logger.Warn("Failed to create polynomial", "err", err)
		return err
	}
	s.feldmanCommitmenter, err = commitment.NewFeldmanCommitmenter(curve, s.poly)
	if err != nil {
		logger.Warn("Failed to create feldmanCommitmenter", "err", err)
		return err
	}

	s.poly = s.poly.Differentiate(s.bk.GetRank())
	s.peerManager.MustSend(id, &Message{
		Type: Type_Result,
		Id:   s.selfId,
		Body: &Message_Result{
			Result: &BodyResult{
				Result: s.feldmanCommitmenter.GetVerifyMessage(peer.bk),
			},
		},
	})
	return peer.AddMessage(msg)
}

func (s *decommitmentHandler) Finalize(logger log.Logger) (types.Handler, error) {
	return newResultHandler(s), nil
}
