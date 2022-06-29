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
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type resultData struct {
	result *ecpointgrouplaw.ECPoint
}

type resultHandler struct {
	*verifyHandler
}

func newResultHandler(v *verifyHandler) *resultHandler {
	return &resultHandler{
		verifyHandler: v,
	}
}

func (p *resultHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Result)
}

func (p *resultHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *resultHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.result != nil
}

func (p *resultHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	siGProofMsg := msg.GetResult().SiGProofMsg
	alphaHat, err := siGProofMsg.Alpha.ToPoint()
	if err != nil {
		logger.Warn("Failed to get point", "err", err)
		return err
	}
	if !peer.decommit.schnorrAPoint.Equal(alphaHat) {
		logger.Warn("Failed to verify Schnorr commitment", "err", err)
		return err
	}

	r, err := siGProofMsg.V.ToPoint()
	if err != nil {
		logger.Warn("Failed to get point", "err", err)
		return err
	}
	err = siGProofMsg.Verify(ecpointgrouplaw.NewBase(p.publicKey.GetCurve()), cggmp.ComputeSSID(p.sid, []byte(peer.peer.bk.String()), p.rid))
	if err != nil {
		logger.Warn("Failed to verify Schorr proof", "err", err)
		return err
	}
	peer.result = &resultData{
		result: r,
	}
	return peer.AddMessage(msg)
}

func (p *resultHandler) Finalize(logger log.Logger) (types.Handler, error) {
	bks := make(birkhoffinterpolation.BkParameters, p.peerNum+1)
	sgs := make([]*ecpointgrouplaw.ECPoint, p.peerNum+1)
	siG, err := p.siGProofMsg.V.ToPoint()
	if err != nil {
		logger.Warn("Failed to get point", "err", err)
		return nil, err
	}
	bks[0] = p.bk
	sgs[0] = siG
	i := 1
	for _, peer := range p.peers {
		bks[i] = peer.peer.bk
		sgs[i] = peer.result.result
		i++
	}
	return nil, bks.ValidatePublicKey(sgs, p.threshold, p.publicKey)
}
