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

package oldpeer

import (
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type computeData struct {
	delta       *big.Int
	siG         *ecpointgrouplaw.ECPoint
	siGProofMsg *zkproof.SchnorrProofMessage
}

type computeHandler struct {
	*peerHandler

	co     *big.Int
	deltaI *big.Int
}

func newComputeHandler(p *peerHandler, co *big.Int, deltaI *big.Int) *computeHandler {
	return &computeHandler{
		peerHandler: p,

		co:     co,
		deltaI: deltaI,
	}
}

func (p *computeHandler) MessageType() types.MessageType {
	return types.MessageType(addshare.Type_Compute)
}

func (p *computeHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *computeHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.compute != nil
}

func (p *computeHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	body := msg.GetCompute()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}
	delta := new(big.Int).SetBytes(body.GetDelta())
	if err := utils.InRange(delta, big.NewInt(0), p.fieldOrder); err != nil {
		logger.Warn("Invalid delta value", "delta", delta.String(), "err", err)
		return err
	}
	siGProofMsg := body.GetSiGProofMsg()
	siG, err := siGProofMsg.V.ToPoint()
	if err != nil {
		logger.Warn("Failed to get point", "err", err)
		return err
	}
	err = siGProofMsg.Verify(ecpointgrouplaw.NewBase(p.pubkey.GetCurve()))
	if err != nil {
		logger.Warn("Failed to verify Schorr proof", "err", err)
		return err
	}
	peer.compute = &computeData{
		delta:       delta,
		siG:         siG,
		siGProofMsg: siGProofMsg,
	}
	return peer.AddMessage(msg)
}

func (p *computeHandler) Finalize(logger log.Logger) (types.Handler, error) {
	// Make delta_i as the sum of delta_j from all old peers (including itself).
	delta := p.deltaI
	for _, peer := range p.peers {
		delta.Add(delta, peer.compute.delta)
	}
	p.deltaI = delta.Mod(delta, p.fieldOrder)

	// Send the new delta_i to the new peer.
	msg := &addshare.Message{
		Type: addshare.Type_Result,
		Id:   p.peerManager.SelfID(),
		Body: &addshare.Message_Result{
			Result: &addshare.BodyResult{
				Delta: p.deltaI.Bytes(),
			},
		},
	}
	p.peerManager.MustSend(p.newPeer.Id, msg)
	return newVerifyHandler(p), nil
}
