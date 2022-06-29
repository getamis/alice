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
	proto "github.com/golang/protobuf/proto"
)

const (
	maxRetry = 5
)

type peerData struct {
	bk          *birkhoffinterpolation.BkParameter
	siG         *ecpointgrouplaw.ECPoint
	siGProofMsg *zkproof.SchnorrProofMessage
}

type peerHandler struct {
	// self information
	fieldOrder  *big.Int
	pubkey      *ecpointgrouplaw.ECPoint
	threshold   uint32
	newPeerRank uint32

	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
}

func newPeerHandler(peerManager types.PeerManager, pubkey *ecpointgrouplaw.ECPoint, threshold, newPeerRank uint32) *peerHandler {
	// Construct peers
	peers := make(map[string]*peer, peerManager.NumPeers())
	for _, peerID := range peerManager.PeerIDs() {
		peers[peerID] = newPeer(peerID)
	}
	return &peerHandler{
		fieldOrder:  pubkey.GetCurve().Params().N,
		pubkey:      pubkey,
		threshold:   threshold,
		newPeerRank: newPeerRank,

		peerManager: peerManager,
		peerNum:     peerManager.NumPeers(),
		peers:       peers,
	}
}

func (p *peerHandler) MessageType() types.MessageType {
	return types.MessageType(addshare.Type_OldPeer)
}

func (p *peerHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *peerHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.peer != nil
}

func (p *peerHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	body := msg.GetOldPeer()

	if p.threshold != body.GetThreshold() {
		logger.Warn("Inconsistent threshold", "got", body.GetThreshold(), "expected", p.threshold)
		return tss.ErrInconsistentThreshold
	}
	bk, err := body.GetBk().ToBk(p.fieldOrder)
	if err != nil {
		logger.Warn("Failed to get bk", "err", err)
		return err
	}
	pubkey, err := body.GetPubkey().ToPoint()
	if err != nil {
		logger.Warn("Failed to get point", "err", err)
		return err
	}
	if !p.pubkey.Equal(pubkey) {
		logger.Warn("Inconsistent public key", "got", pubkey, "expected", p.pubkey)
		return tss.ErrInconsistentPubKey
	}
	siGProofMsg := body.GetSiGProofMsg()
	siG, err := siGProofMsg.V.ToPoint()
	if err != nil {
		logger.Warn("Failed to get point", "err", err)
		return err
	}
	err = siGProofMsg.Verify(ecpointgrouplaw.NewBase(pubkey.GetCurve()))
	if err != nil {
		logger.Warn("Failed to verify Schorr proof", "err", err)
		return err
	}
	peer := newPeer(id)
	peer.peer = &peerData{
		bk:          bk,
		siG:         siG,
		siGProofMsg: siGProofMsg,
	}
	p.peers[id] = peer
	return peer.AddMessage(msg)
}

func (p *peerHandler) Finalize(logger log.Logger) (types.Handler, error) {
	i := 0
	bks := make(birkhoffinterpolation.BkParameters, p.peerNum)
	sgs := make([]*ecpointgrouplaw.ECPoint, p.peerNum)
	for _, peer := range p.peers {
		bks[i] = peer.peer.bk
		sgs[i] = peer.peer.siG
		i++
	}

	// The sum of siG must be equal to the given public key.
	err := bks.ValidatePublicKey(sgs, p.threshold, p.pubkey)
	if err != nil {
		return nil, err
	}

	selfBK, err := generateNewBK(logger, p.fieldOrder, bks, p.threshold, p.newPeerRank)
	if err != nil {
		return nil, err
	}

	msg := &addshare.Message{
		Type: addshare.Type_NewBk,
		Id:   p.peerManager.SelfID(),
		Body: &addshare.Message_NewBk{
			NewBk: &addshare.BodyNewBk{
				Bk: selfBK.ToMessage(),
			},
		},
	}
	p.broadcast(msg)
	return newResultHandler(p, selfBK, bks, sgs), nil
}

func (p *peerHandler) broadcast(msg proto.Message) {
	for id := range p.peers {
		p.peerManager.MustSend(id, msg)
	}
}

func getMessage(messsage types.Message) *addshare.Message {
	return messsage.(*addshare.Message)
}

func getMessageByType(peer *peer, t addshare.Type) *addshare.Message {
	return getMessage(peer.GetMessage(types.MessageType(t)))
}

func generateNewBK(logger log.Logger, fieldOrder *big.Int, bks birkhoffinterpolation.BkParameters, threshold, newPeerRank uint32) (*birkhoffinterpolation.BkParameter, error) {
	var err error
	var x *big.Int
	var selfBK *birkhoffinterpolation.BkParameter

	// Randomize x and build new bk with retry
	for i := 0; i < maxRetry; i++ {
		x, err = utils.RandomPositiveInt(fieldOrder)
		if err != nil {
			logger.Warn("Failed to generate random positive integer", "fieldOrder", fieldOrder, "retryCount", i, "err", err)
			continue
		}
		selfBK = birkhoffinterpolation.NewBkParameter(x, newPeerRank)

		// Check if the bks are ok
		allBks := append(bks, selfBK)
		err = allBks.CheckValid(threshold, fieldOrder)
		if err != nil {
			logger.Warn("Failed to check bks", "newBK", selfBK.String(), "retryCount", i, "err", err)
			continue
		}
		return selfBK, nil
	}
	return nil, err
}
