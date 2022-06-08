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

func NewMulStarMessage(config *CurveConfig, ssidInfo []byte, x, rho, N0, C, D *big.Int, ped *PederssenOpenParameter, X *pt.ECPoint) (*MulStarMessage, error) {
	pedN := ped.Getn()
	peds := ped.Gets()
	pedt := ped.Gett()
	// Sample α in ± 2^{l+ε}
	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomCoprimeInt(N0)
	if err != nil {
		return nil, err
	}
	// Sample γ in ± 2^{l+ε}·Nˆ.
	gamma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpLAddepsilon, pedN))
	if err != nil {
		return nil, err
	}
	m, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpL, pedN))
	if err != nil {
		return nil, err
	}

	N0Square := new(big.Int).Mul(N0, N0)
	A := new(big.Int).Exp(C, alpha, N0Square)
	A.Mul(A, new(big.Int).Exp(r, N0, N0Square))
	A.Mod(A, N0Square)

	G := pt.NewBase(X.GetCurve())
	Bx := G.ScalarMult(alpha)
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgBx, err := Bx.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgX, err := X.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	// E = s^alpha*t^γ mod Nˆ
	E := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, gamma, pedN))
	E.Mod(E, pedN)
	// S = s^x*t^m
	S := new(big.Int).Mul(new(big.Int).Exp(peds, x, pedN), new(big.Int).Exp(pedt, m, pedN))
	S.Mod(S, pedN)

	msgs := append(utils.GetAnyMsg(ssidInfo, pedN.Bytes(), peds.Bytes(), pedt.Bytes(), N0.Bytes(), C.Bytes(), D.Bytes(), A.Bytes(), E.Bytes(), S.Bytes()), msgG, msgX, msgBx)
	e, salt, err := GetE(G.GetCurve().Params().N, msgs...)
	if err != nil {
		return nil, err
	}

	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, x))
	z2 := new(big.Int).Add(gamma, new(big.Int).Mul(e, m))
	w := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, N0))
	w.Mod(w, N0)

	return &MulStarMessage{
		Salt: salt,
		A:    A.Bytes(),
		B:    msgBx,
		Z1:   z1.String(),
		Z2:   z2.String(),
		E:    E.Bytes(),
		S:    S.Bytes(),
		W:    w.Bytes(),
	}, nil

}

func (msg *MulStarMessage) Verify(config *CurveConfig, ssidInfo []byte, N0, C, D *big.Int, ped *PederssenOpenParameter, X *pt.ECPoint) error {
	G := pt.NewBase(X.GetCurve())
	N0Square := new(big.Int).Mul(N0, N0)
	pedN := ped.Getn()
	peds := ped.Gets()
	pedt := ped.Gett()
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgX, err := X.ToEcPointMessage()
	if err != nil {
		return err
	}
	Bx, err := msg.B.ToPoint()
	if err != nil {
		return err
	}
	curveOrder := X.GetCurve().Params().N

	msgs := append(utils.GetAnyMsg(ssidInfo, pedN.Bytes(), peds.Bytes(), pedt.Bytes(), N0.Bytes(), C.Bytes(), D.Bytes(), msg.A, msg.E, msg.S), msgG, msgX, msg.B)
	seed, err := utils.HashProtos(msg.Salt, msgs...)
	if err != nil {
		return err
	}
	e := utils.RandomAbsoluteRangeIntBySeed(msg.Salt, seed, curveOrder)
	err = utils.InRange(e, new(big.Int).Neg(curveOrder), new(big.Int).Add(big1, curveOrder))
	if err != nil {
		return err
	}
	// check A in Z_{N0^2}^\ast, E,S in Z_{\hat{N}}^\ast, w in Z_{N0}^\ast, and e ∈ ±q.
	z1, _ := new(big.Int).SetString(msg.Z1, 10)
	z2, _ := new(big.Int).SetString(msg.Z2, 10)
	w := new(big.Int).SetBytes(msg.W)
	err = utils.InRange(w, big0, N0)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(w, N0) {
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
	S := new(big.Int).SetBytes(msg.S)
	err = utils.InRange(S, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(S, pedN) {
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
	// Check z_1 in ±2^{l+ε}.
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big2, uint(config.LAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	// Check z1*G = B_x + e*X
	BxXexpe := X.ScalarMult(e)
	BxXexpe, err = BxXexpe.Add(Bx)
	if err != nil {
		return err
	}
	gz1 := G.ScalarMult(z1)
	if !gz1.Equal(BxXexpe) {
		return ErrVerifyFailure
	}
	// Check (C)^{z1} ·w^{N_0} =A·D^e mod N_0^2.
	ADexpe := new(big.Int).Mul(A, new(big.Int).Exp(D, e, N0Square))
	ADexpe.Mod(ADexpe, N0Square)
	temp := new(big.Int).Exp(C, z1, N0Square)
	compare := new(big.Int).Exp(w, N0, N0Square)
	compare.Mul(compare, temp)
	compare.Mod(compare, N0Square)
	if compare.Cmp(ADexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check s^{z1}t^{z2} =E·S^e mod Nˆ
	sz1tz3 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z2, pedN))
	sz1tz3.Mod(sz1tz3, pedN)
	ESexpe := new(big.Int).Mul(E, new(big.Int).Exp(S, e, pedN))
	ESexpe.Mod(ESexpe, pedN)
	if sz1tz3.Cmp(ESexpe) != 0 {
		return ErrVerifyFailure
	}
	return nil
}
