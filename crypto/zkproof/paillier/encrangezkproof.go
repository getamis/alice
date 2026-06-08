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

const EncryptRange = "AMIS-Alice-EncryptRange-ZK-v1.0-"

func NewEncryptRangeMessage(config *CurveConfig, ssidInfo []byte, ciphertext *big.Int, proverN *big.Int, k *big.Int, rho *big.Int, ped *PederssenOpenParameter) (*EncryptRangeMessage, error) {
	groupOrder := config.Curve.Params().N
	proverNSquare := new(big.Int).Exp(proverN, big2, nil)
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()
	// Sample α in ± 2^{l+ε}
	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	// Sample μ in ± 2^{l+ε}·Nˆ.
	mu, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpL, pedN))
	if err != nil {
		return nil, err
	}
	// Sample r in Z_{N_0}^ast.
	r, err := utils.RandomCoprimeInt(proverN)
	if err != nil {
		return nil, err
	}
	// Sample γ in ± 2^{l+ε}·Nˆ.
	gamma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpLAddepsilon, pedN))
	if err != nil {
		return nil, err
	}
	// S = s^k*t^μ mod Nˆ
	S := new(big.Int).Mul(new(big.Int).Exp(peds, k, pedN), new(big.Int).Exp(pedt, mu, pedN))
	S.Mod(S, pedN)
	// A = (1+N_0)^α·r^{N_0} mod N_0^2
	A := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, proverN), alpha, proverNSquare), new(big.Int).Exp(r, proverN, proverNSquare))
	A.Mod(A, proverNSquare)
	// C = s^α*t^γ mod Nˆ
	C := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, gamma, pedN))
	C.Mod(C, pedN)

	e, counter, err := GetE(EncryptRange, groupOrder, utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), ciphertext.Bytes(), proverN.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), S.Bytes(), A.Bytes(), C.Bytes())...)
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
		Counter: counter,
		S:       S.Bytes(),
		A:       A.Bytes(),
		C:       C.Bytes(),
		Z1:      z1.String(),
		Z2:      z2.Bytes(),
		Z3:      z3.String(),
	}, nil
}

func (msg *EncryptRangeMessage) Verify(config *CurveConfig, ssidInfo []byte, ciphertext []byte, proveN *big.Int, ped *PederssenOpenParameter) error {
	groupOrder := config.Curve.Params().N
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()

	// Check S ∈ Z_{pedN}^\ast
	S := new(big.Int).SetBytes(msg.S)
	if err := utils.InRange(S, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(S, pedN) {
		return ErrVerifyFailure
	}

	C := new(big.Int).SetBytes(msg.C)
	if err := utils.InRange(C, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(C, pedN) {
		return ErrVerifyFailure
	}

	z1, ok := new(big.Int).SetString(msg.Z1, 10)
	if !ok {
		return ErrInvalidInput
	}
	z3, ok := new(big.Int).SetString(msg.Z3, 10)
	if !ok {
		return ErrInvalidInput
	}

	z2 := new(big.Int).SetBytes(msg.Z2)
	if err := utils.InRange(z2, big0, proveN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(z2, proveN) {
		return ErrVerifyFailure
	}

	K := new(big.Int).SetBytes(ciphertext)
	proveNSqaure := new(big.Int).Exp(proveN, big2, nil)
	if err := utils.InRange(K, big0, proveNSqaure); err != nil {
		return err
	}
	if !utils.IsRelativePrime(K, proveN) {
		return ErrVerifyFailure
	}

	A := new(big.Int).SetBytes(msg.A)
	if err := utils.InRange(A, big0, proveNSqaure); err != nil {
		return err
	}
	if !utils.IsRelativePrime(A, proveN) {
		return ErrVerifyFailure
	}

	msgs := utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), ciphertext, proveN.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), S.Bytes(), A.Bytes(), C.Bytes())
	e, expectedCounter, err := GetE(EncryptRange, groupOrder, msgs...)
	if err != nil {
		return err
	}
	if expectedCounter != msg.Counter {
		return ErrVerifyFailure
	}

	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big1, uint(config.LAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}

	// Check (1+N_0)^{z1} ·z_2^{N_0} = A·K^e mod N_0^2.
	AKexpe := new(big.Int).Mul(A, new(big.Int).Exp(K, e, proveNSqaure))
	AKexpe.Mod(AKexpe, proveNSqaure)

	temp := new(big.Int).Add(big1, proveN)
	temp.Exp(temp, z1, proveNSqaure)
	compare := new(big.Int).Exp(z2, proveN, proveNSqaure)
	compare.Mul(compare, temp)
	compare.Mod(compare, proveNSqaure)

	if compare.Cmp(AKexpe) != 0 {
		return ErrVerifyFailure
	}

	// Check s^{z1}*t^{z3} = C·S^e mod Nˆ
	CSexpe := new(big.Int).Mul(C, new(big.Int).Exp(S, e, pedN))
	CSexpe.Mod(CSexpe, pedN)

	compare = new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z3, pedN))
	compare.Mod(compare, pedN)

	if CSexpe.Cmp(compare) != 0 {
		return ErrVerifyFailure
	}

	return nil
}
