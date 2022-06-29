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
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type verifyData struct {
	siG         *ecpointgrouplaw.ECPoint
	siGProofMsg *zkproof.SchnorrProofMessage
}

type verifyHandler struct {
	*computeHandler
}

func newVerifyHandler(p *computeHandler) *verifyHandler {
	return &verifyHandler{
		computeHandler: p,
	}
}

func (p *verifyHandler) MessageType() types.MessageType {
	return types.MessageType(addshare.Type_Verify)
}

func (p *verifyHandler) GetRequiredMessageCount() uint32 {
	// In this round, old peers only need to get siG from the new peer.
	return uint32(1)
}

func (p *verifyHandler) IsHandled(logger log.Logger, id string) bool {
	if id != p.newPeer.Id {
		logger.Warn("Get message from invalid peer")
		return false
	}
	return p.newPeer.verify != nil
}

func (p *verifyHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	if id != p.newPeer.Id {
		logger.Warn("Get message from invalid peer")
		return tss.ErrInvalidMsg
	}
	body := msg.GetVerify()
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
	p.newPeer.verify = &verifyData{
		siG:         siG,
		siGProofMsg: siGProofMsg,
	}
	return p.newPeer.AddMessage(msg)
}

func (p *verifyHandler) Finalize(logger log.Logger) (types.Handler, error) {
	siG, err := p.siGProofMsg.V.ToPoint()
	if err != nil {
		logger.Warn("Failed to get point", "err", err)
		return nil, err
	}

	// bks = self bk + old peer bk + new peer bk
	// sgs = self siG + old peer siG + new peer siG
	bks := make(birkhoffinterpolation.BkParameters, p.peerNum+2)
	sgs := make([]*ecpointgrouplaw.ECPoint, p.peerNum+2)
	bks[0] = p.bk
	sgs[0] = siG
	i := 1
	for _, peer := range p.peers {
		bks[i] = peer.peer.bk
		sgs[i] = peer.compute.siG
		i++
	}
	// Append new peer siG to sgs and new peer bk to bks.
	sgs[i] = p.newPeer.verify.siG
	bks[i] = p.newPeer.peer.bk

	return nil, bks.ValidatePublicKey(sgs, p.threshold, p.pubkey)
}
