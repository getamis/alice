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

	"github.com/getamis/alice/crypto/cggmp"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type round3Data struct {
	delta *big.Int
}

type round3Handler struct {
	*round2Handler

	sigma *big.Int
	R     *pt.ECPoint
}

func newRound3Handler(round2Handler *round2Handler) (*round3Handler, error) {
	return &round3Handler{
		round2Handler: round2Handler,
	}, nil
}

func (p *round3Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round3)
}

func (p *round3Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round3Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round3Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}
	round3 := msg.GetRound3()
	// Compute r=R|x-axis and σi =km+rχ.
	ownPed := p.own.para
	Delta, err := round3.BigDelta.ToPoint()
	if err != nil {
		logger.Debug("Failed to ToPoint", "err", err)
		return err
	}
	err = round3.Psidoublepai.Verify(parameter, peer.ssidWithBk, peer.round1Data.kOtherCiphertext, peer.para.Getn(), ownPed.Getn(), ownPed.Gets(), ownPed.Gett(), Delta, p.sumGamma)
	if err != nil {
		logger.Debug("Failed to Verify", "err", err)
		return err
	}

	tempDelta, _ := new(big.Int).SetString(round3.Delta, 10)
	peer.round3Data = &round3Data{
		delta: tempDelta,
	}

	return peer.AddMessage(msg)
}

func (p *round3Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	delta := new(big.Int).Set(p.delta)
	bigDelta := p.BigDelta.Copy()
	for _, peer := range p.peers {
		round3 := getMessage(peer.GetMessage(types.MessageType(Type_Round3))).GetRound3()
		Delta, err := round3.BigDelta.ToPoint()
		if err != nil {
			logger.Debug("Failed to ToPoint", "err", err)
			return nil, err
		}

		delta.Add(delta, peer.round3Data.delta)
		bigDelta, err = bigDelta.Add(Delta)
		if err != nil {
			logger.Debug("Failed to Add", "err", err)
			return nil, err
		}
	}

	// Do verification
	gDelta := pt.NewBase(curve).ScalarMult(delta)
	if !gDelta.Equal(bigDelta) {
		// return nil, analysis()
		return nil, errors.New("fix me QQ")
	}
	R := p.sumGamma.ScalarMult(new(big.Int).ModInverse(delta, curveN))
	if R.IsIdentity() {
		logger.Debug("Identity point")
		return nil, ErrZeroR
	}
	r := R.GetX()
	// TODO: replace new(big.Int).SetBytes to new(big.Int).SetBytes(SHA3(m))
	sigma := new(big.Int).Mul(p.k, new(big.Int).SetBytes(p.msg))

	sigma.Add(sigma, new(big.Int).Mul(r, p.chi))
	sigma.Mod(sigma, curveN)

	p.sigma = sigma
	p.R = R
	cggmp.Broadcast(p.peerManager, &Message{
		Id:   p.peerManager.SelfID(),
		Type: Type_Round4,
		Body: &Message_Round4{
			Round4: &Round4Msg{
				Sigmai: sigma.Bytes(),
			},
		},
	})
	return newRound4Handler(p)
}

// func analysis() error {
// 	// A: Reprove that {Dj,i}j ̸=i are well-formed according to prod_ell^aff-g , for l ̸= j,i.
// 	for i := 0; i < len(msgs); i++ {
// 		msg := msgs[i]
// 		proveBK, err := msg.Bk.ToBk(curveN)
// 		if err != nil {
// 			return nil, nil, err
// 		}

// 		ownPed := p.pederssenPara[p.onwBK.GetX().String()]
// 		n := p.pederssenPara[proveBK.GetX().String()].Getn()
// 		proveBKXString := proveBK.GetX().String()
// 		// Verify psi
// 		err = p.psiProof[proveBKXString].Verify(msg.Ssid, p.paillierKey.GetN(), n, p.kCiphertext, p.otherD[proveBKXString], p.otherF[proveBKXString], ownPed.Getn(), ownPed.Gets(), ownPed.Gett(), p.allGammaPoint[proveBKXString])
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 	}
// 	// B: Compute Hi = enci(ki · γi) and prove in ZK that Hi is well formed wrt Ki and Gi in Πmul.
// 	kMulGamma := new(big.Int).Mul(p.gamma, p.k)
// 	kMulGammaCiphertext, randomRho, err := p.paillierKey.EncryptWithOutputSalt(kMulGamma)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	rho := new(big.Int).Exp(p.mu, new(big.Int).Neg(p.k), p.paillierKey.GetNSquare())
// 	rho.Mul(rho, randomRho)
// 	rho.Mod(rho, p.paillierKey.GetNSquare())
// 	proofMul, err := paillierzkproof.NewMulMessage(p.ssid, p.k, rho, p.rho, p.paillierKey.GetN(), p.kCiphertext, p.gammaCiphertext, kMulGammaCiphertext, curveN)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	deltaCiphertext := new(big.Int).Set(kMulGammaCiphertext)
// 	RhoSalt := new(big.Int).Set(randomRho)
// 	alphaDeltaWithSaltOne := new(big.Int).Add(big1, p.paillierKey.GetN())
// 	paillierNnthRoot, err := p.paillierKey.GetNthRoot()
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	tempResult := new(big.Int).Set(kMulGamma)
// 	// C: Prove in ZK that δi is the plaintext value mod q of the ciphertext obtained as Hi*prod_{j\not=i}D_{i,j}*F_{j,i}
// 	for i := 0; i < len(msgs); i++ {
// 		msg := msgs[i]
// 		proveBK, err := msg.Bk.ToBk(curveN)
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		proveBKXString := proveBK.GetX().String()
// 		tempDSalt := new(big.Int).Exp(alphaDeltaWithSaltOne, new(big.Int).Neg(p.otherAlpha[proveBKXString]), p.paillierKey.GetNSquare())
// 		tempDSalt.Mul(tempDSalt, p.otherD[proveBKXString])
// 		tempDSalt.Exp(tempDSalt, paillierNnthRoot, p.paillierKey.GetNSquare())

// 		RhoSalt.Mul(RhoSalt, tempDSalt)
// 		RhoSalt.Mul(RhoSalt, new(big.Int).ModInverse(p.r[proveBKXString], p.paillierKey.GetNSquare()))
// 		RhoSalt.Mod(RhoSalt, p.paillierKey.GetNSquare())

// 		deltaCiphertext.Mul(p.otherD[proveBKXString], deltaCiphertext)
// 		deltaCiphertext.Mul(new(big.Int).ModInverse(p.F[proveBKXString], p.paillierKey.GetNSquare()), deltaCiphertext)
// 		deltaCiphertext.Mod(deltaCiphertext, p.paillierKey.GetNSquare())

// 		tempResult.Add(tempResult, p.otherAlpha[proveBKXString])
// 		tempResult.Add(tempResult, p.beta[proveBKXString])
// 	}

// 	ErrMsg := make(map[string]*DeltaVerifyFailureMsg)
// 	for i := 0; i < len(msgs); i++ {
// 		msg := msgs[i]
// 		proveBK, err := msg.Bk.ToBk(curveN)
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		proveBKXString := proveBK.GetX().String()
// 		ped := p.pederssenPara[proveBKXString]

// 		//fmt.Println("Original:", deltaCiphertext)
// 		translateBeta := new(big.Int).Exp(alphaDeltaWithSaltOne, new(big.Int).Mul(new(big.Int).Neg(p.countDelta), ped.Getn()), p.paillierKey.GetNSquare())
// 		deltaCiphertext.Mul(deltaCiphertext, translateBeta)
// 		deltaCiphertext.Mod(deltaCiphertext, p.paillierKey.GetNSquare())

// 		//fmt.Println("deltaCiphertext:", deltaCiphertext)
// 		ProofDec, err := paillierzkproof.NewDecryMessage(p.ssid, tempResult, RhoSalt, p.paillierKey.GetN(), deltaCiphertext, p.delta, ped.Getn(), ped.Gets(), ped.Gett(), curveN)
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		err = ProofDec.Verify(p.ssid, p.paillierKey.GetN(), deltaCiphertext, p.delta, ped.Getn(), ped.Gets(), ped.Gett(), curveN)

// 		ErrMsg[proveBKXString] = &DeltaVerifyFailureMsg{
// 			Ssid:               p.ssid,
// 			Bk:                 p.onwBK.ToMessage(),
// 			KgammaCiphertext:   kMulGammaCiphertext.Bytes(),
// 			MulProof:           proofMul,
// 			DecryProoof:        ProofDec,
// 			ProductrCiphertext: deltaCiphertext.Bytes(),
// 			Count:              p.countDelta.Bytes(),
// 		}
// 	}
// 	return nil, ErrMsg, ErrDifferentPoint
// }
