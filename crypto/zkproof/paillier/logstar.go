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

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
)

func NewKnowExponentAndPaillierEncryption(config *CurveConfig, ssidInfo []byte, x, rho, C, n0, pedN, peds, pedt *big.Int, X *pt.ECPoint, G *pt.ECPoint) (*LogStarMessage, error) {
	n0Square := new(big.Int).Exp(n0, big2, nil)
	curveN := G.GetCurve().Params().N
	// Sample α in ± 2^{l+ε}, β in ±2^{l'+ε}.
	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	// Sample μ in ± 2^{l+ε}·Nˆ.
	mu, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpL, pedN))
	if err != nil {
		return nil, err
	}
	// Sample r in Z_{N0}^ast
	r, err := utils.RandomCoprimeInt(n0)
	if err != nil {
		return nil, err
	}
	// Sample γ in ± 2^{l+ε}·Nˆ
	gamma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpLAddepsilon, pedN))
	if err != nil {
		return nil, err
	}
	// S = s^x*t^μ mod Nˆ
	S := new(big.Int).Mul(new(big.Int).Exp(peds, x, pedN), new(big.Int).Exp(pedt, mu, pedN))
	S.Mod(S, pedN)
	// A = (1+N_0)^α ·r^{N_0} mod N_0^2
	A := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n0), alpha, n0Square), new(big.Int).Exp(r, n0, n0Square))
	A.Mod(A, n0Square)
	// Y := α*G
	Y := G.ScalarMult(alpha)
	// D = s^α*t^γ
	D := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, gamma, pedN))
	D.Mod(D, pedN)

	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgX, err := X.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgY, err := Y.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	msgs := append(utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), C.Bytes(), S.Bytes(), A.Bytes(), D.Bytes()), msgG, msgX, msgY)
	e, salt, err := GetE(curveN, msgs...)
	if err != nil {
		return nil, err
	}
	// z1 = α+ex
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, x))
	// z2 = r·ρ^e mod N_0
	z2 := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, n0))
	z2.Mod(z2, n0)
	// z3 = γ+eμ
	z3 := new(big.Int).Add(gamma, new(big.Int).Mul(e, mu))

	return &LogStarMessage{
		Salt: salt,
		S:    S.Bytes(),
		A:    A.Bytes(),
		Y:    msgY,
		D:    D.Bytes(),
		Z1:   z1.String(),
		Z2:   z2.Bytes(),
		Z3:   z3.String(),
	}, nil
}

func (msg *LogStarMessage) Verify(config *CurveConfig, ssidInfo []byte, C, n0, pedN, peds, pedt *big.Int, X *pt.ECPoint, G *pt.ECPoint) error {
	n0Square := new(big.Int).Exp(n0, big2, nil)
	curveN := G.GetCurve().Params().N
	S := new(big.Int).SetBytes(msg.S)
	A := new(big.Int).SetBytes(msg.A)
	D := new(big.Int).SetBytes(msg.D)
	z1, _ := new(big.Int).SetString(msg.Z1, 10)
	z2 := new(big.Int).SetBytes(msg.Z2)
	z3, _ := new(big.Int).SetString(msg.Z3, 10)
	Y, err := msg.Y.ToPoint()
	if err != nil {
		return err
	}
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgX, err := X.ToEcPointMessage()
	if err != nil {
		return err
	}

	msgs := append(utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), C.Bytes(), S.Bytes(), A.Bytes(), D.Bytes()), msgG, msgX, msg.Y)
	seed, err := utils.HashProtos(msg.Salt, msgs...)
	if err != nil {
		return err
	}

	e := utils.RandomAbsoluteRangeIntBySeed(seed, curveN)

	err = utils.InRange(e, new(big.Int).Neg(curveN), new(big.Int).Add(big1, curveN))
	if err != nil {
		return err
	}
	// Check (1+N_0)^{z1}z2^{N_0} = A·C^e mod N_0^2.
	AKexpe := new(big.Int).Mul(A, new(big.Int).Exp(C, e, n0Square))
	AKexpe.Mod(AKexpe, n0Square)
	compare := new(big.Int).Exp(z2, n0, n0Square)
	compare.Mul(compare, new(big.Int).Exp(new(big.Int).Add(big1, n0), z1, n0Square))
	compare.Mod(compare, n0Square)
	if compare.Cmp(AKexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check z1*G =Y + e*X
	YXexpe := X.ScalarMult(e)
	YXexpe, err = YXexpe.Add(Y)
	if err != nil {
		return err
	}
	gz1 := G.ScalarMult(z1)
	if !gz1.Equal(YXexpe) {
		return ErrVerifyFailure
	}
	// Check s^{z1}t^{z3} =E·S^e mod Nˆ
	sz1tz3 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z3, pedN))
	sz1tz3.Mod(sz1tz3, pedN)
	DSexpe := new(big.Int).Mul(D, new(big.Int).Exp(S, e, pedN))
	DSexpe.Mod(DSexpe, pedN)
	if sz1tz3.Cmp(DSexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check z_1 in ±2^{l+ε}.
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big2, uint(config.LAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	return nil
}
