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

package newpeer

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type resultData struct {
	delta *big.Int
}

type resultHandler struct {
	*peerHandler

	share *big.Int
	bk    *birkhoffinterpolation.BkParameter
	bks   birkhoffinterpolation.BkParameters
	sgs   []*ecpointgrouplaw.ECPoint
}

func newResultHandler(p *peerHandler, bk *birkhoffinterpolation.BkParameter, bks birkhoffinterpolation.BkParameters, sgs []*ecpointgrouplaw.ECPoint) *resultHandler {
	return &resultHandler{
		peerHandler: p,

		bk:  bk,
		bks: bks,
		sgs: sgs,
	}
}

func (r *resultHandler) MessageType() types.MessageType {
	return types.MessageType(addshare.Type_Result)
}

func (r *resultHandler) GetRequiredMessageCount() uint32 {
	return r.peerNum
}

func (r *resultHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := r.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.result != nil
}

func (r *resultHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	body := msg.GetResult()
	peer, ok := r.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	delta := new(big.Int).SetBytes(body.GetDelta())
	if err := utils.InRange(delta, big.NewInt(0), r.fieldOrder); err != nil {
		logger.Warn("Invalid delta value", "delta", delta.String(), "err", err)
		return err
	}
	peer.result = &resultData{
		delta: delta,
	}
	return peer.AddMessage(msg)
}

func (r *resultHandler) Finalize(logger log.Logger) (types.Handler, error) {
	curve := r.pubkey.GetCurve()

	// Assign new share to sum of delta from all old peers.
	share := big.NewInt(0)
	for _, peer := range r.peers {
		share = new(big.Int).Add(share, peer.result.delta)
	}
	share.Mod(share, r.fieldOrder)
	siG := ecpointgrouplaw.ScalarBaseMult(curve, share)

	// bks = old peer bk + self bk
	// sgs = old peer siG + new siG
	bks := append(r.bks, r.bk)
	sgs := append(r.sgs, siG)
	err := bks.ValidatePublicKey(sgs, r.threshold, r.pubkey)
	if err != nil {
		return nil, err
	}
	r.share = share

	siGProofMsg, err := zkproof.NewBaseSchorrMessage(curve, share)
	if err != nil {
		log.Warn("Failed to new si schorr proof", "err", err)
		return nil, err
	}
	msg := &addshare.Message{
		Type: addshare.Type_Verify,
		Id:   r.peerManager.SelfID(),
		Body: &addshare.Message_Verify{
			Verify: &addshare.BodyVerify{
				SiGProofMsg: siGProofMsg,
			},
		},
	}
	r.broadcast(msg)
	return nil, nil
}
