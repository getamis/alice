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

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	proto "github.com/golang/protobuf/proto"
)

type peerData struct {
	bk            *birkhoffinterpolation.BkParameter
	verifyMessage *Message
}

type commitData struct{}

type commitHandler struct {
	// self information
	publicKey           *ecpointgrouplaw.ECPoint
	oldShare            *big.Int
	bk                  *birkhoffinterpolation.BkParameter
	poly                *polynomial.Polynomial
	threshold           uint32
	feldmanCommitmenter *commitment.FeldmanCommitmenter

	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
}

func newCommitHandler(publicKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, threshold uint32, oldShare *big.Int, bks map[string]*birkhoffinterpolation.BkParameter) (*commitHandler, error) {
	numPeers := peerManager.NumPeers()
	lenBks := len(bks)
	if lenBks != int(numPeers+1) {
		log.Warn("Inconsistent peer num", "bks", len(bks), "numPeers", numPeers)
		return nil, tss.ErrInconsistentPeerNumAndBks
	}
	if err := utils.EnsureThreshold(threshold, uint32(lenBks)); err != nil {
		return nil, err
	}

	curve := publicKey.GetCurve()
	fieldOrder := curve.Params().N
	poly, err := polynomial.RandomPolynomial(fieldOrder, threshold-1)
	if err != nil {
		return nil, err
	}
	poly.SetConstant(big.NewInt(0))

	// Build Feldman commitmenter
	feldmanCommitmenter, err := commitment.NewFeldmanCommitmenter(curve, poly)
	if err != nil {
		return nil, err
	}

	selfBK, peers, err := buildPeers(fieldOrder, peerManager.SelfID(), threshold, bks, feldmanCommitmenter)
	if err != nil {
		log.Warn("Failed to build peers", "err", err)
		return nil, err
	}

	return &commitHandler{
		publicKey:           publicKey,
		oldShare:            oldShare,
		bk:                  selfBK,
		poly:                poly,
		threshold:           threshold,
		feldmanCommitmenter: feldmanCommitmenter,

		peerManager: peerManager,
		peerNum:     numPeers,
		peers:       peers,
	}, nil
}

func (p *commitHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Commit)
}

func (p *commitHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *commitHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.commit != nil
}

func (p *commitHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}
	peer.commit = &commitData{}
	return peer.AddMessage(msg)
}

func (p *commitHandler) Finalize(logger log.Logger) (types.Handler, error) {
	for id, peer := range p.peers {
		p.peerManager.MustSend(id, peer.peer.verifyMessage)
	}
	return newVerifyHandler(p), nil
}

func (p *commitHandler) getCommitMessage() *Message {
	return &Message{
		Type: Type_Commit,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Commit{
			Commit: &BodyCommit{
				PointCommitment: p.feldmanCommitmenter.GetCommitmentMessage(),
			},
		},
	}
}

func (p *commitHandler) broadcast(msg proto.Message) {
	for id := range p.peers {
		p.peerManager.MustSend(id, msg)
	}
}

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}

func getMessageByType(peer *peer, t Type) *Message {
	return getMessage(peer.GetMessage(types.MessageType(t)))
}

func buildPeers(fieldOrder *big.Int, selfID string, threshold uint32, bks map[string]*birkhoffinterpolation.BkParameter, commitmenter *commitment.FeldmanCommitmenter) (*birkhoffinterpolation.BkParameter, map[string]*peer, error) {
	lenBks := len(bks)
	allBKs := make(birkhoffinterpolation.BkParameters, lenBks)
	peers := make(map[string]*peer, lenBks-1)
	var selfBK *birkhoffinterpolation.BkParameter
	i := 0
	for id, bk := range bks {
		allBKs[i] = bk
		i++

		// Build self bk
		if id == selfID {
			selfBK = bk
			continue
		}
		// Build peers
		peer := newPeer(id)
		peer.peer = &peerData{
			bk: bk,
			verifyMessage: &Message{
				Type: Type_Verify,
				Id:   selfID,
				Body: &Message_Verify{
					Verify: &BodyVerify{
						Verify: commitmenter.GetVerifyMessage(bk),
					},
				},
			},
		}
		peers[id] = peer
	}
	if selfBK == nil {
		return nil, nil, tss.ErrSelfBKNotFound
	}

	// Check if the bks are ok
	_, err := allBKs.ComputeBkCoefficient(threshold, fieldOrder)
	if err != nil {
		log.Warn("Failed to compute bkCoefficient", "err", err)
		return nil, nil, err
	}

	return selfBK, peers, nil
}
