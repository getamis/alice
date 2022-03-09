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

package paillier

import (
	"math/big"

	"github.com/getamis/alice/crypto/utils"
)

func NewEncryptRangeMessage(config *CurveConfig, ssidInfo []byte, ciphertext *big.Int, proverN *big.Int, k *big.Int, rho *big.Int, pedersenN *big.Int, pedersenS *big.Int, pedersenT *big.Int) (*EncryptRangeMessage, error) {
	groupOrder := config.Curve.Params().N
	proverNSquare := new(big.Int).Exp(proverN, big2, nil)
	// Sample α in ± 2^{l+ε}
	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	// Sample μ in ± 2^{l+ε}·Nˆ.
	mu, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpL, pedersenN))
	if err != nil {
		return nil, err
	}
	// Sample r in Z_{N_0}^ast.
	r, err := utils.RandomCoprimeInt(proverN)
	if err != nil {
		return nil, err
	}
	// Sample γ in ± 2^{l+ε}·Nˆ.
	gamma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpLAddepsilon, pedersenN))
	if err != nil {
		return nil, err
	}
	// S = s^k*t^μ mod Nˆ
	S := new(big.Int).Mul(new(big.Int).Exp(pedersenS, k, pedersenN), new(big.Int).Exp(pedersenT, mu, pedersenN))
	S.Mod(S, pedersenN)
	// A = (1+N_0)^α·r^{N_0} mod N_0^2
	A := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, proverN), alpha, proverNSquare), new(big.Int).Exp(r, proverN, proverNSquare))
	A.Mod(A, proverNSquare)
	// C = s^α*t^γ mod Nˆ
	C := new(big.Int).Mul(new(big.Int).Exp(pedersenS, alpha, pedersenN), new(big.Int).Exp(pedersenT, gamma, pedersenN))
	C.Mod(C, pedersenN)

	e, salt, err := GetE(groupOrder, utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), ciphertext.Bytes(), S.Bytes(), A.Bytes(), C.Bytes())...)
	if err != nil {
		return nil, err
	}

	// z1 = α+ek
	z1 := new(big.Int).Mul(e, k)
	z1.Add(z1, alpha)
	// z2 = r·ρ^e mod N_0
	z2 := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, proverN))
	z2.Mod(z2, proverN)
	// z3 =γ+eμ
	z3 := new(big.Int).Mul(e, mu)
	z3.Add(z3, gamma)
	return &EncryptRangeMessage{
		Salt: salt,
		S:    S.Bytes(),
		A:    A.Bytes(),
		C:    C.Bytes(),
		Z1:   z1.String(),
		Z2:   z2.Bytes(),
		Z3:   z3.String(),
	}, nil
}

func (msg *EncryptRangeMessage) Verify(config *CurveConfig, ssidInfo []byte, ciphertext []byte, proveN *big.Int, pedersenN, pedersenS, pedersenT *big.Int) error {
	groupOrder := config.Curve.Params().N
	S := new(big.Int).SetBytes(msg.S)
	A := new(big.Int).SetBytes(msg.A)
	C := new(big.Int).SetBytes(msg.C)
	z1, _ := new(big.Int).SetString(msg.Z1, 10)
	z2 := new(big.Int).SetBytes(msg.Z2)
	z3, _ := new(big.Int).SetString(msg.Z3, 10)
	K := new(big.Int).SetBytes(ciphertext)
	proveNSaure := new(big.Int).Exp(proveN, big2, nil)

	seed, err := utils.HashProtos(msg.Salt, utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), ciphertext, S.Bytes(), A.Bytes(), C.Bytes())...)
	if err != nil {
		return err
	}
	e := utils.RandomAbsoluteRangeIntBySeed(seed, groupOrder)
	err = utils.InRange(e, new(big.Int).Neg(groupOrder), new(big.Int).Add(big1, groupOrder))
	if err != nil {
		return err
	}
	// Check (1+N_0)^{z1} ·z_2^{N_0} =A·K^e mod N_0^2.
	AKexpe := new(big.Int).Mul(A, new(big.Int).Exp(K, e, proveNSaure))
	AKexpe.Mod(AKexpe, proveNSaure)
	temp := new(big.Int).Add(big1, proveN)
	temp.Exp(temp, z1, proveNSaure)
	compare := new(big.Int).Exp(z2, proveN, proveNSaure)
	compare.Mul(compare, temp)
	compare.Mod(compare, proveNSaure)
	if compare.Cmp(AKexpe) != 0 {
		return ErrVerifyFailure
	}

	// Check s^{z1}*t^{z3} =C·S^e mod Nˆ
	CSexpe := new(big.Int).Mul(C, new(big.Int).Exp(S, e, pedersenN))
	CSexpe.Mod(CSexpe, pedersenN)
	compare = new(big.Int).Mul(new(big.Int).Exp(pedersenS, z1, pedersenN), new(big.Int).Exp(pedersenT, z3, pedersenN))
	compare.Mod(compare, pedersenN)
	if CSexpe.Cmp(compare) != 0 {
		return ErrVerifyFailure
	}
	// Check z1 ∈ ±2^{l+ε}.
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big2, uint(config.LAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	return nil
}
