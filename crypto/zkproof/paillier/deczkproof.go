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

const (
	SpecialDecryZKDST = "AMIS-Alice-Paillier-Special-Decryption-ZK-v1.0-"
)

func NewDecryMessage(config *CurveConfig, ssidInfo []byte, y, rho, N0, C, x *big.Int, ped *PederssenOpenParameter) (*DecryMessage, error) {
	G := pt.NewBase(config.Curve)
	curveN := config.Curve.Params().N
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()

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

	C_point := G.ScalarMult(alpha)
	msgCPoint, err := C_point.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	msgs := append(utils.GetAnyMsg(ssidInfo, pedN.Bytes(), peds.Bytes(), pedt.Bytes(), A.Bytes(), S.Bytes(), T.Bytes(), N0.Bytes(), C.Bytes(), x.Bytes(), curveN.Bytes()), msgCPoint)
	e, counter, err := GetE(SpecialDecryZKDST, curveN, msgs...)
	if err != nil {
		return nil, err
	}

	// z1 =α+ey
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, y))
	z2 := new(big.Int).Add(v, new(big.Int).Mul(e, mu))
	W := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, N0))
	W.Mod(W, N0)

	return &DecryMessage{
		Counter: counter,
		S:       S.Bytes(),
		T:       T.Bytes(),
		A:       A.Bytes(),
		CPoint:  msgCPoint,
		Z1:      z1.String(),
		Z2:      z2.String(),
		W:       W.Bytes(),
	}, nil
}

// Figure 30: old version
func (msg *DecryMessage) Verify(config *CurveConfig, ssidInfo []byte, N0, C, x *big.Int, ped *PederssenOpenParameter) error {
	G := pt.NewBase(config.Curve)
	fieldOrder := config.Curve.Params().N
	N0Square := new(big.Int).Mul(N0, N0)
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()

	if err := utils.InRange(C, big0, N0Square); err != nil {
		return err
	}
	if !utils.IsRelativePrime(C, N0) {
		return ErrVerifyFailure
	}

	msgs := append(utils.GetAnyMsg(ssidInfo, pedN.Bytes(), peds.Bytes(), pedt.Bytes(), msg.A, msg.S, msg.T, N0.Bytes(), C.Bytes(), x.Bytes(), fieldOrder.Bytes()), msg.CPoint)
	e, expectedCounter, err := GetE(SpecialDecryZKDST, fieldOrder, msgs...)
	if err != nil {
		return err
	}
	if expectedCounter != msg.Counter {
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

	z1, ok := new(big.Int).SetString(msg.Z1, 10)
	if !ok {
		return ErrInvalidInput
	}
	z2, ok := new(big.Int).SetString(msg.Z2, 10)
	if !ok {
		return ErrInvalidInput
	}

	W := new(big.Int).SetBytes(msg.W)
	err = utils.InRange(W, big0, N0)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(W, N0) {
		return ErrVerifyFailure
	}

	// Can remove it
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big1, uint(config.LAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	// Can remove it
	upperBdZ2 := new(big.Int).Mul(new(big.Int).Lsh(big1, uint(config.LAddEpsilon)), pedN)
	absZ2 := new(big.Int).Abs(z2)
	if absZ2.Cmp(upperBdZ2) > 0 {
		return ErrVerifyFailure
	}

	// Check z1 * G == C_point + e * X
	C_point, err := msg.CPoint.ToPoint()
	if err != nil {
		return err
	}
	X_point := G.ScalarMult(x)
	eX := X_point.ScalarMult(e)

	comparePoint, err := C_point.Add(eX)
	if err != nil {
		return err
	}

	z1G := G.ScalarMult(z1)
	if !z1G.Equal(comparePoint) {
		return ErrVerifyFailure
	}

	// Check (1+N_0)^{z1} ·w^{N_0} = A·C^e mod N_0^2.
	ACexpe := new(big.Int).Mul(A, new(big.Int).Exp(C, e, N0Square))
	ACexpe.Mod(ACexpe, N0Square)
	temp := new(big.Int).Add(big1, N0)
	temp.Exp(temp, z1, N0Square)
	compare := new(big.Int).Exp(W, N0, N0Square)
	compare.Mul(compare, temp)
	compare.Mod(compare, N0Square)
	if compare.Cmp(ACexpe) != 0 {
		return ErrVerifyFailure
	}

	// Check s^{z1}t^{z2} = T·S^e mod Nˆ
	sz1tz2 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z2, pedN))
	sz1tz2.Mod(sz1tz2, pedN)
	TSexpe := new(big.Int).Mul(T, new(big.Int).Exp(S, e, pedN))
	TSexpe.Mod(TSexpe, pedN)
	if sz1tz2.Cmp(TSexpe) != 0 {
		return ErrVerifyFailure
	}

	return nil
}
