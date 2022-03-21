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
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

var (
	// ErrZeroS is returned if the s is zero
	ErrZeroS = errors.New("zero s")

	big0 = big.NewInt(0)
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
		return nil, errors.New("fix me")
	}
	p.result = &Result{
		R: p.R.GetX(),
		S: s,
	}
	return nil, nil
}

// func analysis() {
// 	// TODO: A, B, C
// 	// A: Reprove that {Dhatj,i}j ̸=i are well-formed according to prod_ell^aff-g , for l ̸= j,i.
// 	for i := 0; i < len(msgs); i++ {
// 		msg := msgs[i]
// 		proveBK, err := msg.Bk.ToBk(curveN)
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}

// 		ownPed := p.pederssenPara[p.onwBK.GetX().String()]
// 		n := p.pederssenPara[proveBK.GetX().String()].Getn()
// 		proveBKXString := proveBK.GetX().String()
// 		// Verify psi
// 		bkPartialKey := p.partialPubKey[proveBKXString].ScalarMult(p.allBKCoefficient[proveBKXString])
// 		err = p.psihatProoof[proveBKXString].Verify(msg.Ssid, p.paillierKey.GetN(), n, p.kCiphertext, p.otherDhat[proveBKXString], p.otherFhat[proveBKXString], ownPed.Getn(), ownPed.Gets(), ownPed.Gett(), bkPartialKey)
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}
// 	}
// 	// B: Compute Hˆi = enci(ki · xi) and prove in ZK that Hˆi is well-formed wrt Ki and Xi according to Πmul∗, for l ̸= i.
// 	rho, err := utils.RandomCoprimeInt(p.paillierKey.GetNSquare())
// 	if err != nil {
// 		return nil, nil, nil, err
// 	}
// 	Dciphertext := new(big.Int).Exp(p.kCiphertext, p.bkMulShare, p.paillierKey.GetNSquare())
// 	Dciphertext.Mul(Dciphertext, new(big.Int).Exp(rho, p.paillierKey.GetN(), p.paillierKey.GetNSquare()))
// 	Dciphertext.Mod(Dciphertext, p.paillierKey.GetNSquare())

// 	ErrMulMsg := make(map[string]*paillierzkproof.MulStarMessage)
// 	decryptPlaintext := new(big.Int).Mul(p.k, new(big.Int).SetBytes(p.msg))
// 	rkMulBkShare := new(big.Int).Mul(p.bkMulShare, p.k)
// 	decryptPlaintext.Add(decryptPlaintext, rkMulBkShare.Mul(p.R.GetX(), rkMulBkShare))

// 	nSquare := p.paillierKey.GetNSquare()
// 	ciphertext := new(big.Int).Exp(p.kCiphertext, new(big.Int).SetBytes(p.msg), nSquare)
// 	innerProductCiphertext := new(big.Int).Set(Dciphertext)

// 	nthRoot, err := p.paillierKey.GetNthRoot()
// 	if err != nil {
// 		return nil, nil, nil, err
// 	}

// 	for i := 0; i < len(msgs); i++ {
// 		msg := msgs[i]
// 		proveBK, err := msg.Bk.ToBk(curveN)
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}
// 		proveBKXString := proveBK.GetX().String()
// 		ped := p.pederssenPara[proveBKXString]
// 		// Verify psi
// 		proofMulStar, err := paillierzkproof.NewMulStarMessage(p.ssid, p.bkMulShare, rho, p.paillierKey.GetN(), p.kCiphertext, Dciphertext, ped.Getn(), ped.Gets(), ped.Gett(), p.bkpartialPubKey)
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}
// 		//err = proofMulStar.Verify(p.ssid, p.paillierKey.GetN(), p.kCiphertext, Dciphertext, ped.Getn(), ped.Gets(), ped.Gett(), p.bkpartialPubKey)

// 		ErrMulMsg[proveBKXString] = proofMulStar

// 		// C: Prove in ZK that σi is the plaintext value mod q of the ciphertext obtained as K^m·(Hˆi·Dˆi,j·Fˆj,i)^r according to Πdec, for l ̸= i.
// 		temp := new(big.Int).Add(p.otherAlphahat[proveBKXString], p.betahat[proveBKXString])
// 		decryptPlaintext.Add(temp.Mul(temp, p.R.GetX()), decryptPlaintext)

// 		// compute ciphertext
// 		innerProductCiphertext.Mul(p.otherDhat[proveBKXString], innerProductCiphertext)
// 		innerProductCiphertext.Mul(new(big.Int).ModInverse(p.Fhat[proveBKXString], nSquare), innerProductCiphertext)
// 		innerProductCiphertext.Mod(innerProductCiphertext, nSquare)
// 	}
// 	ciphertext.Mul(ciphertext, new(big.Int).Exp(innerProductCiphertext, p.R.GetX(), nSquare))
// 	ciphertext.Mod(ciphertext, nSquare)

// 	ErrDecryMsg := make(map[string]*paillierzkproof.DecryMessage)
// 	for i := 0; i < len(msgs); i++ {
// 		msg := msgs[i]
// 		proveBK, err := msg.Bk.ToBk(curveN)
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}
// 		proveBKXString := proveBK.GetX().String()
// 		ped := p.pederssenPara[proveBKXString]
// 		// Verify

// 		translateBeta := new(big.Int).Exp(new(big.Int).Add(p.paillierKey.GetN(), big1), new(big.Int).Mul(new(big.Int).Neg(new(big.Int).Mul(p.R.GetX(), p.countSigma)), ped.Getn()), p.paillierKey.GetNSquare())
// 		ciphertext.Mul(ciphertext, translateBeta)
// 		ciphertext.Mod(ciphertext, nSquare)

// 		salt := new(big.Int).Exp(new(big.Int).Add(p.paillierKey.GetN(), big1), new(big.Int).Neg(decryptPlaintext), nSquare)
// 		salt.Mul(salt, ciphertext)
// 		salt.Exp(salt, nthRoot, nSquare)

// 		proof, err := paillierzkproof.NewDecryMessage(p.ssid, decryptPlaintext, salt, p.paillierKey.GetN(), ciphertext, p.sigma, ped.Getn(), ped.Gets(), ped.Gett(), curveN)
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}

// 		ErrDecryMsg[proveBKXString] = proof
// 	}

// 	ErrSigmaMsg := make(map[string]*SigmaVerifyFailureMsg)
// 	for i := 0; i < len(msgs); i++ {
// 		msg := msgs[i]
// 		proveBK, err := msg.Bk.ToBk(curveN)
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}
// 		proveBKXString := proveBK.GetX().String()
// 		// Verify psi
// 		ErrSigmaMsg[proveBKXString] = &SigmaVerifyFailureMsg{
// 			Ssid:                  p.ssid,
// 			Bk:                    p.onwBK.ToMessage(),
// 			KMulBkShareCiphertext: Dciphertext.Bytes(),
// 			MulStarProof:          ErrMulMsg[proveBKXString],
// 			DecryProoof:           ErrDecryMsg[proveBKXString],
// 			ProductrCiphertext:    ciphertext.Bytes(),
// 			Count:                 p.countSigma.Bytes(),
// 		}
// 	}
// 	return nil, nil, ErrSigmaMsg, ErrSignatureWrong
// }
