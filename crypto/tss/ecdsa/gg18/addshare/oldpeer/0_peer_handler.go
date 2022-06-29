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

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"github.com/golang/protobuf/proto"
)

type peerData struct {
	bk *birkhoffinterpolation.BkParameter
}

type peerHandler struct {
	// self information
	fieldOrder  *big.Int
	pubkey      *ecpointgrouplaw.ECPoint
	share       *big.Int
	siGProofMsg *zkproof.SchnorrProofMessage
	bk          *birkhoffinterpolation.BkParameter
	threshold   uint32
	newPeer     *peer

	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
}

func newPeerHandler(peerManager types.PeerManager, pubkey *ecpointgrouplaw.ECPoint, threshold uint32, share *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, newPeerID string) (*peerHandler, error) {
	numPeers := peerManager.NumPeers()
	lenBks := len(bks)
	if lenBks != int(numPeers+1) {
		log.Warn("Inconsistent peer num", "bks", len(bks), "numPeers", numPeers)
		return nil, tss.ErrInconsistentPeerNumAndBks
	}
	if err := utils.EnsureThreshold(threshold, uint32(lenBks)); err != nil {
		return nil, err
	}

	curve := pubkey.GetCurve()
	fieldOrder := curve.Params().N
	siGProofMsg, err := zkproof.NewBaseSchorrMessage(curve, share)
	if err != nil {
		log.Warn("Failed to new si schorr proof", "err", err)
		return nil, err
	}

	selfBK, peers, err := buildPeers(fieldOrder, peerManager.SelfID(), threshold, bks, newPeerID)
	if err != nil {
		log.Warn("Failed to build peers", "err", err)
		return nil, err
	}

	return &peerHandler{
		fieldOrder:  fieldOrder,
		pubkey:      pubkey,
		share:       share,
		siGProofMsg: siGProofMsg,
		bk:          selfBK,
		threshold:   threshold,
		newPeer:     newPeer(newPeerID),

		peerManager: peerManager,
		peerNum:     numPeers,
		peers:       peers,
	}, nil
}

func (p *peerHandler) MessageType() types.MessageType {
	return types.MessageType(addshare.Type_NewBk)
}

func (p *peerHandler) GetRequiredMessageCount() uint32 {
	// In this round, old peers only need to get bk from the new peer.
	return uint32(1)
}

func (p *peerHandler) IsHandled(logger log.Logger, id string) bool {
	if id != p.newPeer.Id {
		logger.Warn("Get message from invalid peer")
		return false
	}
	return p.newPeer.peer != nil
}

func (p *peerHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	if id != p.newPeer.Id {
		logger.Warn("Get message from invalid peer")
		return tss.ErrInvalidMsg
	}
	body := msg.GetNewBk()
	bk, err := body.GetBk().ToBk(p.fieldOrder)
	if err != nil {
		logger.Warn("Failed to get bk", "err", err)
		return err
	}

	p.newPeer.peer = &peerData{
		bk: bk,
	}
	return p.newPeer.AddMessage(msg)
}

func (p *peerHandler) Finalize(logger log.Logger) (types.Handler, error) {
	bks := make(birkhoffinterpolation.BkParameters, p.peerNum+1)
	bks[0] = p.bk
	i := 1
	for _, peer := range p.peers {
		bks[i] = peer.peer.bk
		i++
	}

	// Compute delta_i.
	co, err := bks.GetAddShareCoefficient(p.bk, p.newPeer.peer.bk, p.fieldOrder, p.threshold)
	if err != nil {
		logger.Warn("Failed to get coefficient", "err", err)
		return nil, err
	}
	delta := new(big.Int).Mul(co, p.share)

	// Split delta_i to random j pieces.
	// delta_i = delta_i_1 + delta_i_2 +···+ delta_i_t
	deltaIJ := make([]*big.Int, p.peerNum)
	sumDeltaJ := big.NewInt(0)
	for j := 0; j < int(p.peerNum); j++ {
		deltaJ, err := utils.RandomInt(p.fieldOrder)
		if err != nil {
			return nil, err
		}
		sumDeltaJ = new(big.Int).Add(sumDeltaJ, deltaJ)
		deltaIJ[j] = deltaJ
	}
	// Keep the last item itself and make sure it is within the field order.
	deltaI := new(big.Int).Sub(delta, sumDeltaJ)
	deltaI.Mod(deltaI, p.fieldOrder)

	i = 0
	for id := range p.peers {
		// Send delta_i_j and siG to peer j.
		computeMsg := &addshare.Message{
			Type: addshare.Type_Compute,
			Id:   p.peerManager.SelfID(),
			Body: &addshare.Message_Compute{
				Compute: &addshare.BodyCompute{
					Delta:       deltaIJ[i].Bytes(),
					SiGProofMsg: p.siGProofMsg,
				},
			},
		}
		i++
		p.peerManager.MustSend(id, computeMsg)
	}
	return newComputeHandler(p, co, deltaI), nil
}

func (p *peerHandler) getOldPeerMessage() *addshare.Message {
	pubkey, err := p.pubkey.ToEcPointMessage()
	if err != nil {
		log.Warn("Failed to convert public key", "err", err)
		return nil
	}
	return &addshare.Message{
		Type: addshare.Type_OldPeer,
		Id:   p.peerManager.SelfID(),
		Body: &addshare.Message_OldPeer{
			OldPeer: &addshare.BodyOldPeer{
				Bk:          p.bk.ToMessage(),
				SiGProofMsg: p.siGProofMsg,
				Pubkey:      pubkey,
				Threshold:   p.threshold,
			},
		},
	}
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

func buildPeers(fieldOrder *big.Int, selfID string, threshold uint32, bks map[string]*birkhoffinterpolation.BkParameter, newPeerID string) (*birkhoffinterpolation.BkParameter, map[string]*peer, error) {
	lenBks := len(bks)
	allBKs := make(birkhoffinterpolation.BkParameters, lenBks)
	peers := make(map[string]*peer, lenBks+1)
	var selfBK *birkhoffinterpolation.BkParameter
	i := 0
	for id, bk := range bks {
		if id == newPeerID {
			log.Warn("New peer should not have bk")
			return nil, nil, tss.ErrInvalidBK
		}

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
