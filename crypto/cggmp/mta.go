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

package cggmp

import (
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/utils"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
)

var (
	big1         = big.NewInt(1)
	big2         = big.NewInt(2)
	parameter    = paillierzkproof.NewS256()
	curveNSquare = new(big.Int).Mul(parameter.Curve.Params().N, parameter.Curve.Params().N)
)

func MtaWithProofAff_g(ownssid []byte, peerPed *paillierzkproof.PederssenOpenParameter, paillierKey *paillier.Paillier, msgCipher []byte, x *big.Int, ecPoint *pt.ECPoint) (*big.Int, *big.Int, *big.Int, *big.Int, []byte, *big.Int, *paillierzkproof.PaillierAffAndGroupRangeMessage, error) {
	beta, s, r, D, F, err := PerformMTA(peerPed, paillierKey, msgCipher, x)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	peerPaillierKey := paillier.ToPaillierPubKeyWithSpecialG(peerPed)
	proof, err := paillierzkproof.NewPaillierAffAndGroupRangeMessage(parameter, ownssid, x, beta, s, r, peerPed.Getn(), paillierKey.GetN(), new(big.Int).SetBytes(msgCipher), D, F, peerPed, ecPoint)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	adjustBeta, count := computeBeta(beta, peerPaillierKey.GetN(), big.NewInt(0))
	return adjustBeta, count, r, s, D.Bytes(), F, proof, nil
}

func MtaWithProofAff_p(ownssid []byte, peerPed *paillierzkproof.PederssenOpenParameter, paillierKey *paillier.Paillier, msgKCipher []byte, gamma *big.Int, mu *big.Int, gammaCiphertext *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *paillierzkproof.PaillierOperationAndCommitmentMessage, error) {
	beta, s, r, D, F, err := PerformMTA(peerPed, paillierKey, msgKCipher, gamma)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	proof, err := paillierzkproof.NewPaillierOperationAndPaillierCommitment(parameter, ownssid, gamma, beta, s, mu, r, peerPed.Getn(), paillierKey.GetN(), gammaCiphertext, F, new(big.Int).SetBytes(msgKCipher), D, peerPed)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	adjustBeta, _ := computeBeta(beta, peerPed.Getn(), big.NewInt(0))
	return adjustBeta, r, s, D, F, proof, nil
}

func PerformMTA(ped *paillierzkproof.PederssenOpenParameter, paillierKey *paillier.Paillier, msgCipher []byte, x *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
	beta, err := utils.RandomAbsoluteRangeInt(new(big.Int).Lsh(big2, parameter.Lpai))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	// Use other people pubKey: Dj,i = (γi ⊙ Kj) ⊕ encj(βi,j , si,j) and Fj,i = enci(βi,j , ri,j).
	peoplePaillierKey := paillier.ToPaillierPubKeyWithSpecialG(ped)
	D := new(big.Int).Exp(new(big.Int).SetBytes(msgCipher), x, peoplePaillierKey.GetNSquare())
	tempEnc, s, err := peoplePaillierKey.EncryptWithOutputSalt(beta)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	D.Mul(D, tempEnc)
	D.Mod(D, peoplePaillierKey.GetNSquare())
	F, r, err := paillierKey.EncryptWithOutputSalt(beta)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return beta, s, r, D, F, nil
}

// If k*\gamma + beta < 0, we should change beta value.
func computeBeta(beta *big.Int, paillierN *big.Int, count *big.Int) (*big.Int, *big.Int) {
	result := new(big.Int).Neg(beta)
	if beta.Cmp(curveNSquare) < 0 {
		result.Sub(result, paillierN)
		count.Add(count, big1)
	}
	return result, count
}
