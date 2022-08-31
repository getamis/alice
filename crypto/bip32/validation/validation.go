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

package validation

import (
	"crypto/subtle"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/utils"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/golang/protobuf/ptypes/any"
)

var (
	big1    = big.NewInt(1)
	big2    = big.NewInt(2)
	bit256  = new(big.Int).Lsh(big1, 128)
	bit1024 = new(big.Int).Lsh(big1, 256*5)

	parameter = paillierzkproof.NewS256()

	// ErrEncryptionMsgWrong is returned if the encrypted message is wrong.
	ErrEncryptionMsgWrong = errors.New("the encrypted message is wrong")
	// ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure.")
)

type ValidationManager struct {
	ssidInfo []byte
	h        *big.Int
	enchSalt *big.Int
	encNegh  *big.Int

	paillierKey *paillier.Paillier
	ownPed      *paillier.PederssenParameter
	otherPed    *paillier.PederssenParameter
}

func NewValidationManager(h *big.Int, ownPaillier *paillier.Paillier, ownPed, otherPed *paillier.PederssenParameter) *ValidationManager {
	return &ValidationManager{
		h:           h,
		paillierKey: ownPaillier,
		otherPed:    otherPed,
		ownPed:      ownPed,
	}
}

func (vad *ValidationManager) OverWriteh(h *big.Int) {
	vad.h = h
}

func (vad *ValidationManager) Round1() (*Round1Message, error) {
	//proverN := vad.paillierKey.GetN()
	negH := new(big.Int).Neg(vad.h)
	e, r, err := vad.paillierKey.EncryptWithOutputSalt(negH)
	if err != nil {
		return nil, err
	}
	// psiProof, err := paillierzkproof.NewEncryptRangeMessage(parameter, vad.ssidInfo, e, proverN, negH, r, vad.otherPed.PedersenOpenParameter)
	// if err != nil {
	// 	return nil, err
	// }
	vad.enchSalt = r
	vad.encNegh = e
	return &Round1Message{
		EncH: e.Bytes(),
		//Psi:  psiProof,
	}, nil
}

func (vad *ValidationManager) Round2(msg1 *Round1Message) (*Round2Message, error) {
	n := vad.otherPed.PedersenOpenParameter.Getn()
	// Verify proof
	// psi := msg1.Psi
	// err := psi.Verify(parameter, vad.ssidInfo, msg1.EncH, n, vad.ownPed.PedersenOpenParameter)
	// if err != nil {
	// 	return nil, err
	// }
	encMsh := new(big.Int).SetBytes(msg1.EncH)

	otherPaillierPubKey := paillier.ToPaillierPubKeyWithSpecialG(vad.otherPed.PedersenOpenParameter)
	nSquare := new(big.Int).Mul(n, n)
	if encMsh.Cmp(nSquare) >= 0 {
		return nil, ErrEncryptionMsgWrong
	}
	s, err := utils.RandomAbsoluteRangeInt(bit1024)
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomAbsoluteRangeInt(bit256)
	if err != nil {
		return nil, err
	}
	e0rPower := new(big.Int).Exp(encMsh, r, nSquare)
	rhaAdds := new(big.Int).Mul(r, vad.h)
	rhaAdds.Add(rhaAdds, s)

	//rhaAdds.Mod(rhaAdds, n)
	encrhAdds, _, err := otherPaillierPubKey.EncryptWithOutputSalt(rhaAdds)
	result := new(big.Int).Mul(e0rPower, encrhAdds)
	result.Mod(result, nSquare)
	sString := s.String()
	hashResult, err := utils.HashProtos([]byte(sString), &any.Any{
		Value: vad.h.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	// proof, err := paillierzkproof.NewSimplifyPaillierOperationAndPaillierCommitment(parameter, vad.ssidInfo, r, rhaAdds, encrhAddsSalt, n, encMsh, result, vad.otherPed.PedersenOpenParameter)
	// if err != nil {
	// 	return nil, err
	// }
	return &Round2Message{
		EncResponse:       result.Bytes(),
		CompareHashResult: hashResult,
		//Proof:             proof,
	}, nil
}

func (vad *ValidationManager) Round3(msg2 *Round2Message) error {
	encMsg := msg2.EncResponse
	// err := msg2.Proof.Verify(parameter, vad.ssidInfo, vad.paillierKey.GetN(), vad.encNegh, new(big.Int).SetBytes(encMsg), vad.ownPed.PedersenOpenParameter)
	// if err != nil {
	// 	return err
	// }

	s, err := vad.paillierKey.Decrypt(encMsg)
	if err != nil {
		return err
	}
	sByte := new(big.Int).SetBytes(s)
	halfN := new(big.Int).Rsh(vad.paillierKey.GetN(), 1)
	if sByte.Cmp(halfN) >= 0 {
		sByte.Sub(sByte, vad.paillierKey.GetN())
	}
	ownHashResult, err := utils.HashProtos([]byte(sByte.String()), &any.Any{
		Value: vad.h.Bytes(),
	})
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(ownHashResult, msg2.CompareHashResult) != 1 {
		return ErrVerifyFailure
	}
	return nil
}
