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
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/sirius/log"
)

type peerData struct {
	bk *birkhoffinterpolation.BkParameter
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

func newCommitHandler(peerManager types.PeerManager, threshold uint32, publicKey *ecpointgrouplaw.ECPoint, oldShare *big.Int, bks map[string]*birkhoffinterpolation.BkParameter) (*commitHandler, error) {
	curve := publicKey.GetCurve()
	params := curve.Params()
	fieldOrder := params.N
	poly, err := polynomial.RandomPolynomial(fieldOrder, threshold-1)
	if err != nil {
		return nil, err
	}
	poly.SetConstant(big.NewInt(0))

	if err := utils.EnsureThreshold(threshold, peerManager.NumPeers()+1); err != nil {
		return nil, err
	}

	allBKs := make(birkhoffinterpolation.BkParameters, len(bks))
	peers := make(map[string]*peer, peerManager.NumPeers())
	var selfBK *birkhoffinterpolation.BkParameter
	i := 0
	for id, bk := range bks {
		allBKs[i] = bk
		i++

		// Build self bk
		if id == peerManager.SelfID() {
			selfBK = bk
			continue
		}
		// Build peer bk
		peer := newPeer(id)
		peer.peer = &peerData{
			bk: bk,
		}
		peers[id] = peer
	}
	if selfBK == nil {
		return nil, tss.ErrSelfBKNotFound
	}

	// Check if the bks are ok
	_, err = allBKs.ComputeBkCoefficient(threshold, fieldOrder)
	if err != nil {
		log.Warn("Failed to compute bkCoefficient", "err", err)
		return nil, err
	}

	// Build Feldman commitmenter
	feldmanCommitmenter, err := commitment.NewFeldmanCommitmenter(curve, poly)
	if err != nil {
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
		peerNum:     peerManager.NumPeers(),
		peers:       peers,
	}, nil
}

func (p *commitHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Commit)
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
		// Build and send the verify message to the corresponding participant.
		v := p.feldmanCommitmenter.GetVerifyMessage(peer.peer.bk)
		msg := &Message{
			Type: Type_Verify,
			Id:   p.peerManager.SelfID(),
			Body: &Message_Verify{
				Verify: &BodyVerify{
					Verify: v,
				},
			},
		}
		p.peerManager.MustSend(id, msg)
	}
	return newVerifyHandler(p), nil
}

func (p *commitHandler) GetCommitMessage() *Message {
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

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}

func getMessageByType(peer *peer, t Type) *Message {
	return getMessage(peer.GetMessage(types.MessageType(t)))
}
