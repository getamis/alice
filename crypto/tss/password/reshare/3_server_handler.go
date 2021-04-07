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

package reshare

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/message/types"
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
	n := p.curve.Params().N
	xuInverse := new(big.Int).ModInverse(peer.bk.GetX(), n)
	err := p.oldShareGVerifier.Verify(user3.OldShareGProver3)
	if err != nil {
		logger.Debug("Failed to verify (old share)", "err", err)
		return err
	}
	err = p.newShareGVerifier.Verify(user3.NewShareGProver3)
	if err != nil {
		logger.Debug("Failed to verify (new share)", "err", err)
		return err
	}

	self := p.peers[p.peerManager.SelfID()]
	// Feldman relation
	evaluation := new(big.Int).SetBytes(user3.Evaluation)
	a0G := p.oldShareGVerifier.GetV().ScalarMult(peer.bkCoefficient)
	a1G, err := p.newShareGVerifier.GetV().Add(a0G.Neg())
	if err != nil {
		logger.Debug("Failed to add neg a0G", "err", err)
		return err
	}
	a1G = a1G.ScalarMult(xuInverse)
	err = commitment.FeldmanVerify(p.curve, self.bk, []*ecpointgrouplaw.ECPoint{a0G, a1G}, 1, evaluation)
	if err != nil {
		logger.Debug("Failed to feldman verify", "err", err)
		return err
	}

	// Calculate new share
	s1 := new(big.Int).Mul(p.secret, self.bkCoefficient)
	s2 := new(big.Int).Sub(peer.bk.GetX(), self.bk.GetX())
	p.newShare = new(big.Int).Mul(new(big.Int).Mul(s1, s2), xuInverse)
	p.newShare = new(big.Int).Mod(new(big.Int).Add(evaluation, p.newShare), n)

	// Validate consistent public key
	err = validatePubKey(logger, self.bkCoefficient, ecpointgrouplaw.ScalarBaseMult(p.curve, p.newShare), peer.bkCoefficient, p.newShareGVerifier.GetV(), p.publicKey)
	if err != nil {
		return err
	}
	return peer.AddMessage(msg)
}

func (p *serverHandler3) Finalize(logger log.Logger) (types.Handler, error) {
	return nil, nil
}
