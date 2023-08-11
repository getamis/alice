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
	"github.com/golang/protobuf/proto"
)

func NewPaillierAffAndGroupRangeMessage(config *CurveConfig, ssidInfo []byte, x *big.Int, y *big.Int, rho *big.Int, rhoy *big.Int, n0 *big.Int, n1 *big.Int, C *big.Int, D *big.Int, Y *big.Int, ped *PederssenOpenParameter, X *pt.ECPoint) (*PaillierAffAndGroupRangeMessage, error) {
	G := pt.NewBase(X.GetCurve())
	curveN := G.GetCurve().Params().N
	n0Square := new(big.Int).Exp(n0, big2, nil)
	n1Square := new(big.Int).Exp(n1, big2, nil)
	pedN := ped.Getn()
	peds := ped.Gets()
	pedt := ped.Gett()

	// Sample α in ± 2^{l+ε}, β in ±2^{l'+ε}.
	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	beta, err := utils.RandomAbsoluteRangeInt(config.TwoExpLpaiAddepsilon)
	if err != nil {
		return nil, err
	}
	// Sample r in Z_{N_0}^*, r_y in Z_{N_1}^*
	r, err := utils.RandomCoprimeInt(n0)
	if err != nil {
		return nil, err
	}
	ry, err := utils.RandomCoprimeInt(n1)
	if err != nil {
		return nil, err
	}
	// Sample γ in ± 2^{l+ε}·Nˆ and m in ±2^l ·Nˆ
	twoLAddEpsilonMulPedN := new(big.Int).Mul(config.TwoExpLAddepsilon, pedN)
	twoLMulPedN := new(big.Int).Mul(config.TwoExpL, pedN)
	gamma, err := utils.RandomAbsoluteRangeInt(twoLAddEpsilonMulPedN)
	if err != nil {
		return nil, err
	}
	m, err := utils.RandomAbsoluteRangeInt(twoLMulPedN)
	if err != nil {
		return nil, err
	}
	// δ in ± 2^{l+ε}·Nˆ and μ in ± 2^{l+ε}·Nˆ
	delta, err := utils.RandomAbsoluteRangeInt(twoLAddEpsilonMulPedN)
	if err != nil {
		return nil, err
	}
	mu, err := utils.RandomAbsoluteRangeInt(twoLMulPedN)
	if err != nil {
		return nil, err
	}
	// A = C^α · ((1+N_0)^β·r^{N_0}) mod N_0^2
	A := new(big.Int).Mul(new(big.Int).Exp(C, alpha, n0Square), new(big.Int).Exp(r, n0, n0Square))
	A.Mul(A, new(big.Int).Exp(new(big.Int).Add(big1, n0), beta, n0Square))
	A.Mod(A, n0Square)

	// B_x = α*G
	Bx := G.ScalarMult(alpha)
	// B_y = (1+N_1)^β ·r^{N_1} mod N_1^2
	By := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n1), beta, n1Square), new(big.Int).Exp(ry, n1, n1Square))
	By.Mod(By, n1Square)
	// E = s^α*t^γ mod Nˆ and S = s^x*t^m mod Nˆ
	E := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, gamma, pedN))
	E.Mod(E, pedN)
	S := new(big.Int).Mul(new(big.Int).Exp(peds, x, pedN), new(big.Int).Exp(pedt, m, pedN))
	S.Mod(S, pedN)
	// F = s^β*t^δ mod Nˆ and T = s^y*t^μ mod Nˆ
	F := new(big.Int).Mul(new(big.Int).Exp(peds, beta, pedN), new(big.Int).Exp(pedt, delta, pedN))
	F.Mod(F, pedN)
	T := new(big.Int).Mul(new(big.Int).Exp(peds, y, pedN), new(big.Int).Exp(pedt, mu, pedN))
	T.Mod(T, pedN)

	msgBx, err := Bx.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	// e in ±q.
	msgs := utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), new(big.Int).SetUint64(config.LpaiAddEpsilon).Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), n0.Bytes(), n1.Bytes(), C.Bytes(), D.Bytes(), Y.Bytes(), S.Bytes(), T.Bytes(), A.Bytes(), By.Bytes(), E.Bytes(), F.Bytes(), G.GetX().Bytes(), G.GetY().Bytes(), X.GetX().Bytes(), X.GetY().Bytes(), Bx.GetX().Bytes(), Bx.GetY().Bytes())
	e, salt, err := GetE(curveN, msgs...)
	if err != nil {
		return nil, err
	}
	// z1 = α + ex, z2 =β+ey, z3 = γ + em, z4 =δ+eμ, w = r · ρ^e mod N_0 and w_y = r_y · ρ_y^e mod N1.
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, x))
	z2 := new(big.Int).Add(beta, new(big.Int).Mul(e, y))
	z3 := new(big.Int).Add(gamma, new(big.Int).Mul(e, m))
	z4 := new(big.Int).Add(delta, new(big.Int).Mul(e, mu))
	w := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, n0))
	w.Mod(w, n0)
	wy := new(big.Int).Mul(ry, new(big.Int).Exp(rhoy, e, n1))
	wy.Mod(wy, n1)
	return &PaillierAffAndGroupRangeMessage{
		Salt: salt,
		S:    S.Bytes(),
		T:    T.Bytes(),
		A:    A.Bytes(),
		Bx:   msgBx,
		By:   By.Bytes(),
		E:    E.Bytes(),
		F:    F.Bytes(),
		Z1:   z1.String(),
		Z2:   z2.String(),
		Z3:   z3.String(),
		Z4:   z4.String(),
		W:    w.Bytes(),
		Wy:   wy.Bytes(),
	}, nil
}

func (msg *PaillierAffAndGroupRangeMessage) Verify(config *CurveConfig, ssidInfo []byte, n0, n1, C, D, Y *big.Int, ped *PederssenOpenParameter, X *pt.ECPoint) error {
	G := pt.NewBase(X.GetCurve())
	curveN := G.GetCurve().Params().N
	n0Square := new(big.Int).Exp(n0, big2, nil)
	n1Square := new(big.Int).Exp(n1, big2, nil)
	pedN := ped.Getn()
	peds := ped.Gets()
	pedt := ped.Gett()
	// check A in Z_{N0^2}^\ast, By in Z_{N1^2}^\ast, E,S,T,F in Z_{\hat{N}}^\ast, w in Z_{N0}^\ast, and wy in Z_{N1}^\ast.
	S := new(big.Int).SetBytes(msg.S)
	err := utils.InRange(S, big0, pedN)
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
	err = utils.InRange(A, big0, n0Square)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(A, n0) {
		return ErrVerifyFailure
	}
	By := new(big.Int).SetBytes(msg.By)
	err = utils.InRange(By, big0, n1Square)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(By, n1) {
		return ErrVerifyFailure
	}
	E := new(big.Int).SetBytes(msg.E)
	err = utils.InRange(E, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(E, pedN) {
		return ErrVerifyFailure
	}
	F := new(big.Int).SetBytes(msg.F)
	err = utils.InRange(F, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(F, pedN) {
		return ErrVerifyFailure
	}
	z1, ok := new(big.Int).SetString(msg.Z1, 10)
	if !ok {
		return ErrInvalidInput
	}
	z2, ok := new(big.Int).SetString(msg.Z2, 10)
	if !ok {
		return ErrInvalidInput
	}
	z3, ok := new(big.Int).SetString(msg.Z3, 10)
	if !ok {
		return ErrInvalidInput
	}
	z4, ok := new(big.Int).SetString(msg.Z4, 10)
	if !ok {
		return ErrInvalidInput
	}
	W := new(big.Int).SetBytes(msg.W)
	err = utils.InRange(W, big0, n0)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(W, n0) {
		return ErrVerifyFailure
	}
	Wy := new(big.Int).SetBytes(msg.Wy)
	err = utils.InRange(Wy, big0, n1)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(Wy, n1) {
		return ErrVerifyFailure
	}
	Bx, err := msg.Bx.ToPoint()
	if err != nil {
		return err
	}

	msgs := utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), new(big.Int).SetUint64(config.LpaiAddEpsilon).Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), n0.Bytes(), n1.Bytes(), C.Bytes(), D.Bytes(), Y.Bytes(), S.Bytes(), T.Bytes(), A.Bytes(), By.Bytes(), E.Bytes(), F.Bytes(), G.GetX().Bytes(), G.GetY().Bytes(), X.GetX().Bytes(), X.GetY().Bytes(), Bx.GetX().Bytes(), Bx.GetY().Bytes())
	seed, err := utils.HashProtos(msg.Salt, msgs...)
	if err != nil {
		return err
	}
	e := utils.RandomAbsoluteRangeIntBySeed(msg.Salt, seed, curveN)
	err = utils.InRange(e, new(big.Int).Neg(curveN), new(big.Int).Add(big1, curveN))
	if err != nil {
		return err
	}
	// Check z_1 in ±2^{l+ε}.
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big2, uint(config.LAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	// Check z_2 in ±2^{l′+ε}.
	absZ2 := new(big.Int).Abs(z2)
	if absZ2.Cmp(new(big.Int).Lsh(big2, uint(config.LpaiAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	// Check z1*G =B_x + e*X
	BxXexpe := X.ScalarMult(e)
	BxXexpe, err = BxXexpe.Add(Bx)
	if err != nil {
		return err
	}
	gz1 := G.ScalarMult(z1)
	if !gz1.Equal(BxXexpe) {
		return ErrVerifyFailure
	}
	// Check C^{z1}(1+N_0)^{z2}w^{N_0} = A·D^e mod N_0^2.
	ADexpe := new(big.Int).Mul(A, new(big.Int).Exp(D, e, n0Square))
	ADexpe.Mod(ADexpe, n0Square)
	compare := new(big.Int).Exp(C, z1, n0Square)
	compare.Mul(compare, new(big.Int).Exp(new(big.Int).Add(big1, n0), z2, n0Square))
	compare.Mul(compare, new(big.Int).Exp(W, n0, n0Square))
	compare.Mod(compare, n0Square)
	if compare.Cmp(ADexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check (1+N_1)^{z_2}wy^{N_1} = B_y·Y^e mod N_1^2.
	Byyexpe := new(big.Int).Mul(By, new(big.Int).Exp(Y, e, n1Square))
	Byyexpe.Mod(Byyexpe, n1Square)
	compare = new(big.Int).Exp(Wy, n1, n1Square)
	compare.Mul(compare, new(big.Int).Exp(new(big.Int).Add(big1, n1), z2, n1Square))
	compare.Mod(compare, n1Square)
	if compare.Cmp(Byyexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check s^{z1}t^{z3} =E·S^e mod Nˆ
	sz1tz3 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z3, pedN))
	sz1tz3.Mod(sz1tz3, pedN)
	ESexpe := new(big.Int).Mul(E, new(big.Int).Exp(S, e, pedN))
	ESexpe.Mod(ESexpe, pedN)
	if sz1tz3.Cmp(ESexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check s^{z2}t^{z4} =F·T^e mod Nˆ
	sz2tz4 := new(big.Int).Mul(new(big.Int).Exp(peds, z2, pedN), new(big.Int).Exp(pedt, z4, pedN))
	sz2tz4.Mod(sz2tz4, pedN)
	FTexpe := new(big.Int).Mul(F, new(big.Int).Exp(T, e, pedN))
	FTexpe.Mod(FTexpe, pedN)
	if FTexpe.Cmp(sz2tz4) != 0 {
		return ErrVerifyFailure
	}
	return nil
}

func GetE(groupOrder *big.Int, msgs ...proto.Message) (*big.Int, []byte, error) {
	for j := 0; j < maxRetry; j++ {
		salt, err := utils.GenRandomBytes(128)
		if err != nil {
			return nil, nil, err
		}
		seedMsg, err := utils.HashProtos(salt, msgs...)
		if err != nil {
			return nil, nil, err
		}

		// Assume that the length of yi is 32 byte
		// e should belongs in [-q, q]
		e := utils.RandomAbsoluteRangeIntBySeed(salt, seedMsg, groupOrder)
		absoluteE := new(big.Int).Abs(e)
		if absoluteE.Cmp(groupOrder) <= 0 {
			return e, salt, nil
		}
	}
	return nil, nil, ErrExceedMaxRetry
}
