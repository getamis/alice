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

package sign

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/utils"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

const (
	BYTELENGTHKAPPA = 32
)

var (
	ErrNotEnoughRanks = errors.New("not enough ranks")

	parameter = paillierzkproof.NewS256()
)

type round1Data struct {
	countDelta *big.Int
	beta       *big.Int
	s          *big.Int
	r          *big.Int
	D          []byte
	F          *big.Int

	countSigma      *big.Int
	betahat         *big.Int
	shat            *big.Int
	rhat            *big.Int
	Dhat            []byte
	Fhat            *big.Int
	gammaCiphertext *big.Int
	kCiphertext     *big.Int
}

type round1Handler struct {
	bkMulShare      *big.Int
	pubKey          *pt.ECPoint
	paillierKey     *paillier.Paillier
	bkpartialPubKey *pt.ECPoint
	msg             []byte

	delta    *big.Int
	chi      *big.Int
	BigDelta *pt.ECPoint

	k           *big.Int
	rho         *big.Int
	kCiphertext *big.Int

	gamma           *big.Int
	mu              *big.Int
	gammaCiphertext *big.Int

	sumGamma *pt.ECPoint

	bks     map[string]*birkhoffinterpolation.BkParameter
	bkShare *big.Int

	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
	own         *peer
}

func newRound1Handler(threshold uint32, ssid []byte, share *big.Int, pubKey *pt.ECPoint, partialPubKey, allY map[string]*pt.ECPoint, paillierKey *paillier.Paillier, ped map[string]*paillierzkproof.PederssenOpenParameter, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte, peerManager types.PeerManager) (*round1Handler, error) {
	curveN := pubKey.GetCurve().Params().N
	// Establish BK Coefficient:
	selfId := peerManager.SelfID()
	ownBK := bks[peerManager.SelfID()]
	bkss := birkhoffinterpolation.BkParameters{
		ownBK,
	}
	ids := []string{
		selfId,
	}
	for id, bk := range bks {
		if id == selfId {
			continue
		}
		bkss = append(bkss, bk)
		ids = append(ids, id)
	}
	err := bkss.CheckValid(threshold, curveN)
	if err != nil {
		return nil, err
	}

	// Build peers
	bkcoefficient, err := bkss.ComputeBkCoefficient(threshold, curveN)
	if err != nil {
		return nil, err
	}
	peers := make(map[string]*peer, peerManager.NumPeers())
	for i, id := range ids {
		if id == selfId {
			continue
		}
		peers[id] = newPeer(id, ssid, bks[id], bkcoefficient[i], ped[id], partialPubKey[id], allY[id])
	}
	bkShare := new(big.Int).Mul(share, bkcoefficient[0])
	bkShare.Mod(bkShare, curveN)

	// Build and send round1 message
	// k, γ in F_q
	k, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}
	gamma, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}
	// Gi = enc_i(γ, mu), and Ki = enc(k, ρ)
	kCiphertext, rho, err := paillierKey.EncryptWithOutputSalt(k)
	if err != nil {
		return nil, err
	}
	gammaCiphertext, mu, err := paillierKey.EncryptWithOutputSalt(gamma)
	if err != nil {
		return nil, err
	}

	// Set data
	own := newPeer(selfId, ssid, ownBK, bkcoefficient[0], ped[selfId], partialPubKey[selfId], allY[selfId])
	return &round1Handler{
		bkMulShare:      bkShare,
		pubKey:          pubKey,
		paillierKey:     paillierKey,
		bkpartialPubKey: own.partialPubKey.ScalarMult(own.bkcoefficient),
		msg:             msg,

		k:               k,
		rho:             rho,
		gamma:           gamma,
		mu:              mu,
		gammaCiphertext: gammaCiphertext,
		kCiphertext:     kCiphertext,

		bks:     bks,
		bkShare: bkShare,

		peerManager: peerManager,
		peerNum:     peerManager.NumPeers(),
		peers:       peers,
		own:         own,
	}, nil
}

func (p *round1Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round1)
}

func (p *round1Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round1Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round1Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	curve := p.pubKey.GetCurve()
	// Compute Gamma = gamma*G
	Gamma := pt.ScalarBaseMult(curve, p.gamma)
	msgGamma, err := Gamma.ToEcPointMessage()
	if err != nil {
		return err
	}

	round1 := msg.GetRound1()
	ownPed := p.own.para
	peerPed := peer.para
	n := peerPed.Getn()

	// verify Proof_enc
	err = round1.Psi.Verify(parameter, p.own.ssidWithBk, round1.KCiphertext, n, ownPed)
	if err != nil {
		return err
	}
	negBeta, countDelta, r, s, D, F, phiProof, err := cggmp.MtaWithProofAff_g(p.own.ssidWithBk, peer.para, p.paillierKey, round1.KCiphertext, p.gamma, Gamma)
	if err != nil {
		return err
	}
	// psihat share proof: M(prove,Πaff-g,(sid,i),(Iε,Jε,Dˆj,i,Kj,Fˆj,i,Xi);(xi,βˆi,j,sˆi,j,rˆi,j)).
	negBetahat, countSigma, rhat, shat, Dhat, Fhat, psihatProof, err := cggmp.MtaWithProofAff_g(p.own.ssidWithBk, peer.para, p.paillierKey, round1.KCiphertext, p.bkMulShare, p.bkpartialPubKey)
	if err != nil {
		return err
	}

	peer.round1Data = &round1Data{
		countDelta:      countDelta,
		beta:            negBeta,
		r:               r,
		s:               s,
		D:               D,
		F:               F,
		gammaCiphertext: new(big.Int).SetBytes(round1.GammaCiphertext),
		kCiphertext:     new(big.Int).SetBytes(round1.KCiphertext),

		countSigma: countSigma,
		betahat:    negBetahat,
		rhat:       rhat,
		shat:       shat,
		Dhat:       Dhat,
		Fhat:       Fhat,
	}

	// logstar proof for the secret gamma, mu: M(prove,Πlog,(sid,i),(Iε,Gi,Γi,g);(γi,νi)).
	G := pt.NewBase(curve)
	psipaiProof, err := paillierzkproof.NewKnowExponentAndPaillierEncryption(parameter, p.own.ssidWithBk, p.gamma, p.mu, p.gammaCiphertext, p.paillierKey.GetN(), peerPed, Gamma, G)
	if err != nil {
		return err
	}
	p.peerManager.MustSend(id, &Message{
		Id:   p.own.Id,
		Type: Type_Round2,
		Body: &Message_Round2{
			Round2: &Round2Msg{
				D:      D,
				F:      F.Bytes(),
				Dhat:   Dhat,
				Fhat:   Fhat.Bytes(),
				Psi:    phiProof,
				Psihat: psihatProof,
				Psipai: psipaiProof,
				Gamma:  msgGamma,
			},
		},
	})
	return peer.AddMessage(msg)
}

func (p *round1Handler) Finalize(logger log.Logger) (types.Handler, error) {
	return newRound2Handler(p)
}

func (p *round1Handler) sendRound1Messages() error {
	n := p.paillierKey.GetN()
	selfId := p.peerManager.SelfID()
	for id, peer := range p.peers {
		// Compute proof psi_{j,i}^0
		psi, err := paillierzkproof.NewEncryptRangeMessage(parameter, peer.ssidWithBk, p.kCiphertext, n, p.k, p.rho, peer.para)
		if err != nil {
			return err
		}
		p.peerManager.MustSend(id, &Message{
			Id:   selfId,
			Type: Type_Round1,
			Body: &Message_Round1{
				Round1: &Round1Msg{
					KCiphertext:     p.kCiphertext.Bytes(),
					GammaCiphertext: p.gammaCiphertext.Bytes(),
					Psi:             psi,
				},
			},
		})
	}
	return nil
}

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}
