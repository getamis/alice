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
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	// ErrZeroS is returned if the s is zero
	ErrZeroS = errors.New("zero s")

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
)

type Result struct {
	R *big.Int
	S *big.Int
}

type round4Data struct {
	sigma *big.Int
}

type round4Handler struct {
	*round3Handler

	result *Result

	err2Msg *Message
}

func newRound4Handler(round3Handler *round3Handler) (*round4Handler, error) {
	return &round4Handler{
		round3Handler: round3Handler,
	}, nil
}

func (p *round4Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round4)
}

func (p *round4Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round4Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round4Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	round4 := msg.GetRound4()
	peer.round4Data = &round4Data{
		sigma: new(big.Int).SetBytes(round4.Sigmai),
	}
	return peer.AddMessage(msg)
}

func (p *round4Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curveN := p.pubKey.GetCurve().Params().N
	// Set σ=sum_j σj.
	s := new(big.Int).Set(p.sigma)
	for _, peer := range p.peers {
		s.Add(s, peer.round4Data.sigma)
	}
	s.Mod(s, curveN)
	if s.Cmp(big0) == 0 {
		return nil, ErrZeroS
	}

	// Verify that (r,s) is a correct signature
	isCorrectSig := ecdsa.Verify(p.pubKey.ToPubKey(), p.msg, p.R.GetX(), s)
	if !isCorrectSig {
		err := p.buildSigmaVerifyFailureMsg()
		if err != nil {
			logger.Warn("Failed to buildSigmaVerifyFailureMsg", "err", err)
		}
		return nil, errors.New("incorrect sig")
	}
	p.result = &Result{
		R: p.R.GetX(),
		S: s,
	}
	return nil, nil
}

func (p *round4Handler) buildSigmaVerifyFailureMsg() error {
	// A: Reprove that {Dhatj,i}j ̸=i are well-formed according to prod_ell^aff-g , for l ̸= j,i.
	for _, peer := range p.peers {
		ownPed := p.own.para
		n := peer.para.Getn()
		// Verify psi
		bkPartialKey := peer.partialPubKey.ScalarMult(peer.bkcoefficient)
		err := peer.round2Data.psihatProoof.Verify(paillierzkproof.NewS256(), peer.ssidWithBk, p.paillierKey.GetN(), n, p.kCiphertext, peer.round2Data.dhat, peer.round2Data.fhat, ownPed, bkPartialKey)
		if err != nil {
			return err
		}
	}
	// B: Compute Hˆi = enci(ki · xi) and prove in ZK that Hˆi is well-formed wrt Ki and Xi according to Πmul∗, for l ̸= i.
	rho, err := utils.RandomCoprimeInt(p.paillierKey.GetNSquare())
	if err != nil {
		return err
	}
	dciphertext := new(big.Int).Exp(p.kCiphertext, p.bkMulShare, p.paillierKey.GetNSquare())
	dciphertext.Mul(dciphertext, new(big.Int).Exp(rho, p.paillierKey.GetN(), p.paillierKey.GetNSquare()))
	dciphertext.Mod(dciphertext, p.paillierKey.GetNSquare())

	decryptPlaintext := new(big.Int).Mul(p.k, new(big.Int).SetBytes(p.msg))
	rkMulBkShare := new(big.Int).Mul(p.bkMulShare, p.k)
	decryptPlaintext.Add(decryptPlaintext, rkMulBkShare.Mul(p.R.GetX(), rkMulBkShare))

	nSquare := p.paillierKey.GetNSquare()
	ciphertext := new(big.Int).Exp(p.kCiphertext, new(big.Int).SetBytes(p.msg), nSquare)
	innerProductCiphertext := new(big.Int).Set(dciphertext)
	nthRoot, err := p.paillierKey.GetNthRoot()
	if err != nil {
		return err
	}

	// Compute MulStarProof
	peersMsg := make(map[string]*Err2PeerMsg, len(p.peers))
	for _, peer := range p.peers {
		ped := peer.para
		// Verify psi and build proofMulStar
		proofMulStar, err := paillierzkproof.NewMulStarMessage(paillierzkproof.NewS256(), p.own.ssidWithBk, p.bkMulShare, rho, p.paillierKey.GetN(), p.kCiphertext, dciphertext, ped, p.bkpartialPubKey)
		if err != nil {
			return err
		}
		peersMsg[peer.bk.String()] = &Err2PeerMsg{
			MulStarProof: proofMulStar,
			Count:        peer.round1Data.countSigma.Bytes(),
		}

		// C: Prove in ZK that σi is the plaintext value mod q of the ciphertext obtained as K^m·(Hˆi·Dˆi,j·Fˆj,i)^r according to Πdec, for l ̸= i.
		temp := new(big.Int).Add(peer.round2Data.alphahat, peer.round1Data.betahat)
		decryptPlaintext.Add(temp.Mul(temp, p.R.GetX()), decryptPlaintext)

		// compute ciphertext
		innerProductCiphertext.Mul(p.own.round2Data.dhat, innerProductCiphertext)
		innerProductCiphertext.Mul(new(big.Int).ModInverse(peer.round2Data.fhat, nSquare), innerProductCiphertext)
		innerProductCiphertext.Mod(innerProductCiphertext, nSquare)
	}

	// Build ciphertext
	ciphertext.Mul(ciphertext, new(big.Int).Exp(innerProductCiphertext, p.R.GetX(), nSquare))
	ciphertext.Mod(ciphertext, nSquare)

	// Build DecryProoof
	for _, peer := range p.peers {
		ped := peer.para
		translateBeta := new(big.Int).Exp(new(big.Int).Add(p.paillierKey.GetN(), big1), new(big.Int).Mul(new(big.Int).Neg(new(big.Int).Mul(p.R.GetX(), peer.round1Data.countSigma)), ped.Getn()), p.paillierKey.GetNSquare())
		ciphertext.Mul(ciphertext, translateBeta)
		ciphertext.Mod(ciphertext, nSquare)

		salt := new(big.Int).Exp(new(big.Int).Add(p.paillierKey.GetN(), big1), new(big.Int).Neg(decryptPlaintext), nSquare)
		salt.Mul(salt, ciphertext)
		salt.Exp(salt, nthRoot, nSquare)

		proof, err := paillierzkproof.NewDecryMessage(paillierzkproof.NewS256(), p.own.ssidWithBk, decryptPlaintext, salt, p.paillierKey.GetN(), ciphertext, p.sigma, ped)
		if err != nil {
			return err
		}
		peersMsg[peer.Id].DecryProoof = proof
	}

	p.err2Msg = &Message{
		Id:   p.peerManager.SelfID(),
		Type: Type_Err2,
		Body: &Message_Err2{
			Err2: &Err2Msg{
				KMulBkShareCiphertext: dciphertext.Bytes(),
				ProductrCiphertext:    ciphertext.Bytes(),
				Peers:                 peersMsg,
			},
		},
	}
	return nil
}
