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

package signer

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/elliptic"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/mta"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	proto "github.com/golang/protobuf/proto"
)

var (
	ErrPeerNotFound = errors.New("peer message not found")
)

type pubkeyData struct {
	publicKey homo.Pubkey
	aigCommit *commitment.HashCommitmentMessage
}

type pubkeyHandler struct {
	wi        *big.Int
	msg       []byte
	publicKey *pt.ECPoint

	g              *pt.ECPoint
	aiMta          mta.Mta
	homo           homo.Crypto
	agCommitmenter *commitment.HashCommitmenter

	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
}

func newPubkeyHandler(publicKey *pt.ECPoint, peerManager types.PeerManager, homo homo.Crypto, secret *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte) (*pubkeyHandler, error) {
	numPeers := peerManager.NumPeers()
	lenBks := len(bks)
	if lenBks != int(numPeers+1) {
		log.Warn("Inconsistent peer num", "bks", len(bks), "numPeers", numPeers)
		return nil, tss.ErrInconsistentPeerNumAndBks
	}

	// Build mta for ai, g
	curve := publicKey.GetCurve()
	aiMta, err := mta.NewMta(curve.Params().N, homo)
	if err != nil {
		log.Warn("Failed to new ai mta", "err", err)
		return nil, err
	}

	// Build committer for ag
	// bit length / 8(to bytes) * 2(x and y point)
	p := aiMta.GetAG(curve)
	agCommitmenter, err := commitment.NewCommitterByPoint(p)
	if err != nil {
		log.Warn("Failed to new an ag hash commiter", "err", err)
		return nil, err
	}

	wi, peers, err := buildWiAndPeers(curve.Params().N, bks, peerManager.SelfID(), secret)
	if err != nil {
		log.Warn("Failed to build wi and peers", "err", err)
		return nil, err
	}
	return &pubkeyHandler{
		wi:        wi,
		msg:       msg,
		publicKey: publicKey,

		g:              pt.NewBase(curve),
		aiMta:          aiMta,
		agCommitmenter: agCommitmenter,
		homo:           homo,

		peerManager: peerManager,
		peerNum:     numPeers,
		peers:       peers,
	}, nil
}

func (p *pubkeyHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Pubkey)
}

func (p *pubkeyHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *pubkeyHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.pubkey != nil
}

func (p *pubkeyHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetPubkey()
	// Verify public key
	publicKey, err := p.homo.NewPubKeyFromBytes(body.Pubkey)
	if err != nil {
		logger.Warn("Failed to get public key", "err", err)
		return err
	}

	peer.pubkey = &pubkeyData{
		publicKey: publicKey,
		aigCommit: body.AgCommitment,
	}
	return peer.AddMessage(msg)
}

func (p *pubkeyHandler) Finalize(logger log.Logger) (types.Handler, error) {
	msg := p.getEnckMessage()
	p.broadcast(msg)
	return newEncKHandler(p)
}

func (p *pubkeyHandler) getPubkeyMessage() *Message {
	return &Message{
		Type: Type_Pubkey,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Pubkey{
			Pubkey: &BodyPublicKey{
				Pubkey:       p.homo.GetPubKey().ToPubKeyBytes(),
				AgCommitment: p.agCommitmenter.GetCommitmentMessage(),
			},
		},
	}
}

func (p *pubkeyHandler) getEnckMessage() *Message {
	return &Message{
		Type: Type_EncK,
		Id:   p.peerManager.SelfID(),
		Body: &Message_EncK{
			EncK: &BodyEncK{
				Enck: p.aiMta.GetEncK(),
			},
		},
	}
}

func (p *pubkeyHandler) getCurve() elliptic.Curve {
	return p.publicKey.GetCurve()
}

func (p *pubkeyHandler) getN() *big.Int {
	return p.getCurve().Params().N
}

func (p *pubkeyHandler) broadcast(msg proto.Message) {
	for id := range p.peers {
		p.peerManager.MustSend(id, msg)
	}
}

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}

func buildWiAndPeers(curveN *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, selfId string, secret *big.Int) (*big.Int, map[string]*peer, error) {
	lenBks := len(bks)
	// Find self bk
	allBks := make(birkhoffinterpolation.BkParameters, lenBks)
	selfBk, ok := bks[selfId]
	if !ok {
		return nil, nil, tss.ErrSelfBKNotFound
	}
	allBks[0] = selfBk

	peers := make(map[string]*peer, lenBks-1)
	i := 1
	for id, bk := range bks {
		// Skip self bk
		if id == selfId {
			continue
		}

		allBks[i] = bk
		i++
		peers[id] = newPeer(id)
	}

	scalars, err := allBks.ComputeBkCoefficient(uint32(lenBks), curveN)
	if err != nil {
		log.Warn("Failed to compute bk coefficient", "allBks", allBks, "err", err)
		return nil, nil, err
	}
	wi := new(big.Int).Mul(secret, scalars[0])
	wi = new(big.Int).Mod(wi, curveN)
	return wi, peers, nil
}
