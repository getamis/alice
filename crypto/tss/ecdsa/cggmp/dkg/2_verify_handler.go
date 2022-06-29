// Copyright © 2022 AMIS Technologies
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

package dkg

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	// ErrTrivialPublicKey is returned the public key is the identity element
	ErrTrivialPublicKey = errors.New("the publickey is the identity element")
)

type verifyData struct {
	verify *commitment.FeldmanVerifyMessage
}

type verifyHandler struct {
	*decommitHandler
	publicKey   *ecpointgrouplaw.ECPoint
	share       *big.Int
	siGProofMsg *zkproof.SchnorrProofMessage
}

func newVerifyHandler(d *decommitHandler) *verifyHandler {
	return &verifyHandler{
		decommitHandler: d,
	}
}

func (p *verifyHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Verify)
}

func (p *verifyHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *verifyHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.verify != nil
}

func (p *verifyHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	// Feldman Verify
	verify := msg.GetVerify().GetVerify()
	decommitMessage := getMessageByType(peer, Type_Decommit)
	err := verify.Verify(decommitMessage.GetDecommit().GetPointCommitment(), p.bk, p.threshold-1)
	if err != nil {
		logger.Warn("Failed to verify message", "err", err)
		return err
	}
	peer.verify = &verifyData{
		verify: verify,
	}
	return peer.AddMessage(msg)
}

func (p *verifyHandler) Finalize(logger log.Logger) (types.Handler, error) {
	// Build the public key, the sum of uG
	var err error
	publicKey := p.u0g.Copy()
	for _, peer := range p.peers {
		publicKey, err = publicKey.Add(peer.decommit.u0g)
		if err != nil {
			logger.Warn("Failed to add ug", "err", err)
			return nil, err
		}
	}
	// The verification of ECDSA does not permit the public key is the identity element.
	if publicKey.IsIdentity() {
		return nil, ErrTrivialPublicKey
	}
	p.publicKey = publicKey

	// Build the share, the sum of f^(n_j)(x_j)
	poly := p.poly.Differentiate(p.bk.GetRank())
	p.share = poly.Evaluate(p.bk.GetX())
	for _, peer := range p.peers {
		v := peer.verify.verify
		p.share = new(big.Int).Add(p.share, new(big.Int).SetBytes(v.Evaluation))
	}
	p.share = new(big.Int).Mod(p.share, p.fieldOrder)

	// XOR all ridis
	rid := bytes.Repeat([]byte{0}, LenRidi)
	copy(rid, p.peerHandler.ridi)
	for _, peer := range p.peers {
		rid = utils.Xor(rid, peer.decommit.ridi)
	}
	p.rid = rid

	// Build and send out the result message
	big0 := big.NewInt(0)
	p.siGProofMsg, err = zkproof.NewSchnorrMessageWithGivenMN(p.share, big0, p.peerHandler.schnorrAValue, big0, ecpointgrouplaw.NewBase(p.publicKey.GetCurve()), cggmp.ComputeSSID(p.sid, []byte(p.bk.String()), p.rid))
	if err != nil {
		log.Warn("Failed to new si schorr proof", "err", err)
		return nil, err
	}
	msg := p.getResultMessage()
	cggmp.Broadcast(p.peerManager, msg)
	return newResultHandler(p), nil
}

func (p *verifyHandler) getResultMessage() *Message {
	return &Message{
		Type: Type_Result,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Result{
			Result: &BodyResult{
				SiGProofMsg: p.siGProofMsg,
			},
		},
	}
}
