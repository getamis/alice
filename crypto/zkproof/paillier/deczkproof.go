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

func NewDecryMessage(config *CurveConfig, ssidInfo []byte, y, rho, N0, C, x *big.Int, ped *PederssenOpenParameter) (*DecryMessage, error) {
	pedN := ped.Getn()
	peds := ped.Gets()
	pedt := ped.Gett()
	// Sample α in ± 2^{l+ε}.
	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	twoLAddEpsilonMulPedN := new(big.Int).Mul(config.TwoExpLAddepsilon, pedN)
	twoLMulPedN := new(big.Int).Mul(config.TwoExpL, pedN)
	mu, err := utils.RandomAbsoluteRangeInt(twoLMulPedN)
	if err != nil {
		return nil, err
	}
	v, err := utils.RandomAbsoluteRangeInt(twoLAddEpsilonMulPedN)
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomCoprimeInt(N0)
	if err != nil {
		return nil, err
	}

	N0Square := new(big.Int).Mul(N0, N0)

	// S = s^y*t^μ mod Nˆ
	S := new(big.Int).Mul(new(big.Int).Exp(peds, y, pedN), new(big.Int).Exp(pedt, mu, pedN))
	S.Mod(S, pedN)
	// T = s^α*t^ν
	T := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, v, pedN))
	T.Mod(T, pedN)
	// A = (1+N_0)^α ·r^{N_0} mod N_0^2
	A := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, N0), alpha, N0Square), new(big.Int).Exp(r, N0, N0Square))
	A.Mod(A, N0Square)
	gamma := new(big.Int).Set(alpha)
	gamma.Mod(gamma, config.Curve.Params().N)

	e, salt, err := GetE(config.Curve.Params().N, utils.GetAnyMsg(ssidInfo, pedN.Bytes(), peds.Bytes(), pedt.Bytes(), A.Bytes(), gamma.Bytes(), S.Bytes(), T.Bytes(), N0.Bytes(), C.Bytes(), x.Bytes(), config.Curve.Params().N.Bytes())...)
	if err != nil {
		return nil, err
	}

	// z1 =α+ey
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, y))
	z2 := new(big.Int).Add(v, new(big.Int).Mul(e, mu))
	W := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, N0))
	W.Mod(W, N0)

	return &DecryMessage{
		Salt:  salt,
		S:     S.Bytes(),
		T:     T.Bytes(),
		A:     A.Bytes(),
		Gamma: gamma.Bytes(),
		Z1:    z1.String(),
		Z2:    z2.String(),
		W:     W.Bytes(),
	}, nil

}

func (msg *DecryMessage) Verify(config *CurveConfig, ssidInfo []byte, N0, C, x *big.Int, ped *PederssenOpenParameter) error {
	fieldOrder := config.Curve.Params().N
	N0Square := new(big.Int).Mul(N0, N0)
	pedN := ped.Getn()
	peds := ped.Gets()
	pedt := ped.Gett()
	seed, err := utils.HashProtos(msg.Salt, utils.GetAnyMsg(ssidInfo, pedN.Bytes(), peds.Bytes(), pedt.Bytes(), msg.A, msg.Gamma, msg.S, msg.T, N0.Bytes(), C.Bytes(), x.Bytes(), fieldOrder.Bytes())...)
	if err != nil {
		return err
	}
	// check A in Z_{N^2}^\ast, S, T in Z_{\hat{N}}^\ast, \gamma \in [0, q), w in Z_{N_0}^\ast, and e in ±q.
	e := utils.RandomAbsoluteRangeIntBySeed(msg.Salt, seed, fieldOrder)
	err = utils.InRange(e, new(big.Int).Neg(fieldOrder), new(big.Int).Add(big1, fieldOrder))
	if err != nil {
		return err
	}

	S := new(big.Int).SetBytes(msg.S)
	err = utils.InRange(S, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(S, pedN) {
		return ErrVerifyFailure
	}
	T := new(big.Int).SetBytes(msg.T)
	err = utils.InRange(T, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(T, pedN) {
		return ErrVerifyFailure
	}
	A := new(big.Int).SetBytes(msg.A)
	err = utils.InRange(A, big0, N0Square)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(A, N0Square) {
		return ErrVerifyFailure
	}
	gamma := new(big.Int).SetBytes(msg.Gamma)
	err = utils.InRange(gamma, big0, fieldOrder)
	if err != nil {
		return err
	}
	z1, _ := new(big.Int).SetString(msg.Z1, 10)
	z2, _ := new(big.Int).SetString(msg.Z2, 10)
	W := new(big.Int).SetBytes(msg.W)
	err = utils.InRange(W, big0, N0)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(W, N0) {
		return ErrVerifyFailure
	}
	// Check
	compare := new(big.Int).Add(gamma, new(big.Int).Mul(e, x))
	compare.Mod(compare, fieldOrder)
	z1ModCurveOrder := new(big.Int).Mod(z1, fieldOrder)
	if compare.Cmp(z1ModCurveOrder) != 0 {
		return ErrVerifyFailure
	}
	// Check (1+N_0)^{z1} ·w^{N_0} =A·C^e mod N_0^2.
	ACexpe := new(big.Int).Mul(A, new(big.Int).Exp(C, e, N0Square))
	ACexpe.Mod(ACexpe, N0Square)
	temp := new(big.Int).Add(big1, N0)
	temp.Exp(temp, z1, N0Square)
	compare = new(big.Int).Exp(W, N0, N0Square)
	compare.Mul(compare, temp)
	compare.Mod(compare, N0Square)
	if compare.Cmp(ACexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check s^{z1}t^{z2} =T·S^e mod Nˆ
	sz1tz2 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z2, pedN))
	sz1tz2.Mod(sz1tz2, pedN)
	TSexpe := new(big.Int).Mul(T, new(big.Int).Exp(S, e, pedN))
	TSexpe.Mod(TSexpe, pedN)
	if sz1tz2.Cmp(TSexpe) != 0 {
		return ErrVerifyFailure
	}
	return nil
}
