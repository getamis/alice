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
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/mta"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/message/types"
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

	minSaltSize    int
	g              *pt.ECPoint
	aiMta          *mta.Mta
	homo           homo.Crypto
	agCommitmenter *commitment.HashCommitmenter

	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
}

func newPubkeyHandler(publicKey *pt.ECPoint, peerManager types.PeerManager, homo homo.Crypto, wi *big.Int, msg []byte) (*pubkeyHandler, error) {
	curve := publicKey.GetCurve()
	// Build mta for ai, g
	aiMta, err := mta.NewMta(curve.Params().N, homo)
	if err != nil {
		log.Warn("Failed to new ai mta", "err", err)
		return nil, err
	}

	// Build committer for ag
	// bit length / 8(to bytes) * 2(x and y point)
	p := aiMta.GetAG(curve)
	minSaltSize := curve.Params().BitSize / 4
	agCommitmenter, err := tss.NewCommitterByPoint(p, minSaltSize)
	if err != nil {
		log.Warn("Failed to new an ag hash commiter", "err", err)
		return nil, err
	}
	return &pubkeyHandler{
		wi:        wi,
		msg:       msg,
		publicKey: publicKey,

		minSaltSize:    minSaltSize,
		g:              pt.NewBase(curve),
		aiMta:          aiMta,
		agCommitmenter: agCommitmenter,
		homo:           homo,

		peerManager: peerManager,
		peerNum:     peerManager.NumPeers(),
		peers:       make(map[string]*peer, peerManager.NumPeers()),
	}, nil
}

func (p *pubkeyHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Pubkey)
}

func (p *pubkeyHandler) IsHandled(logger log.Logger, id string) bool {
	_, ok := p.peers[id]
	return ok
}

func (p *pubkeyHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	body := msg.GetPubkey()

	// Verify public key
	publicKey, err := p.homo.NewPubKeyFromBytes(body.Pubkey)
	if err != nil {
		logger.Warn("Failed to get public key", "err", err)
		return err
	}

	peer := newPeer(id)
	peer.pubkey = &pubkeyData{
		publicKey: publicKey,
		aigCommit: body.AgCommitment,
	}
	p.peers[id] = peer
	return peer.AddMessage(msg)
}

func (p *pubkeyHandler) Finalize(logger log.Logger) (types.Handler, error) {
	msg, err := p.getEnckMessage()
	if err != nil {
		logger.Warn("Failed to get enck message", "err", err)
		return nil, err
	}
	p.broadcast(msg)
	return newEncKHandler(p)
}

func (p *pubkeyHandler) GetPubkeyMessage() *Message {
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

func (p *pubkeyHandler) getEnckMessage() (*Message, error) {
	encK, err := p.aiMta.GetEncK()
	if err != nil {
		log.Warn("Failed to get enc k", "err", err)
		return nil, err
	}
	return &Message{
		Type: Type_EncK,
		Id:   p.peerManager.SelfID(),
		Body: &Message_EncK{
			EncK: &BodyEncK{
				Enck: encK,
			},
		},
	}, nil
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
