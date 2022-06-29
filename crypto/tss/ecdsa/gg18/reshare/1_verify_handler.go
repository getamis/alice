// Copyright © 2020 AMIS Technologies
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
	"math/big"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type verifyData struct{}

type verifyHandler struct {
	*commitHandler
	newShare    *big.Int
	siGProofMsg *zkproof.SchnorrProofMessage
}

func newVerifyHandler(c *commitHandler) *verifyHandler {
	return &verifyHandler{
		commitHandler: c,
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
	commitMessage := getMessageByType(peer, Type_Commit)
	err := verify.Verify(commitMessage.GetCommit().GetPointCommitment(), p.bk, p.threshold-1)
	if err != nil {
		logger.Warn("Failed to verify message", "err", err)
		return err
	}
	peer.verify = &verifyData{}
	return peer.AddMessage(msg)
}

func (p *verifyHandler) Finalize(logger log.Logger) (types.Handler, error) {
	var err error

	// Build the new share, the sum of f^(n_j)(x_j) plus the original share
	poly := p.poly.Differentiate(p.bk.GetRank())
	p.newShare = new(big.Int).Add(p.oldShare, poly.Evaluate(p.bk.GetX()))
	for _, peer := range p.peers {
		v := getMessageByType(peer, Type_Verify).GetVerify().GetVerify()
		p.newShare = new(big.Int).Add(p.newShare, new(big.Int).SetBytes(v.Evaluation))
	}
	p.newShare = new(big.Int).Mod(p.newShare, p.publicKey.GetCurve().Params().N)

	// Build and send out the result message
	p.siGProofMsg, err = zkproof.NewBaseSchorrMessage(p.publicKey.GetCurve(), p.newShare)
	if err != nil {
		log.Warn("Failed to new si schorr proof", "err", err)
		return nil, err
	}

	msg := p.getResultMessage()
	p.broadcast(msg)
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
