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

const KnowExponentAndPaillierEncryption = "AMIS-Alice-KnowExponentAndPaillierEncryption-ZK-v1.0-"

func NewKnowExponentAndPaillierEncryption(config *CurveConfig, ssidInfo []byte, x, rho, C, n0 *big.Int, ped *PederssenOpenParameter, X *pt.ECPoint, G *pt.ECPoint) (*LogStarMessage, error) {
	n0Square := new(big.Int).Exp(n0, big2, nil)
	curveN := G.GetCurve().Params().N
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()

	eBits := uint(curveN.BitLen()) 
	xBits := uint(config.L)       

	// α (alpha) = len(x) + len(e) + epsilon
	safeAlphaBits := xBits + eBits + uint(config.LAddEpsilon)
	safeAlphaBound := new(big.Int).Lsh(big1, safeAlphaBits)
	alpha, err := utils.RandomAbsoluteRangeInt(safeAlphaBound)
	if err != nil {
		return nil, err
	}

	// μ (mu) = len(x) + L
	safeMuBits := xBits + uint(config.L)
	safeMuBound := new(big.Int).Mul(new(big.Int).Lsh(big1, safeMuBits), pedN)
	mu, err := utils.RandomAbsoluteRangeInt(safeMuBound)
	if err != nil {
		return nil, err
	}

	// r in Z_{N0}^ast (維持原樣)
	r, err := utils.RandomCoprimeInt(n0)
	if err != nil {
		return nil, err
	}

	// γ (gamma) = len(μ) + len(e) + epsilon
	safeGammaBits := safeMuBits + eBits + uint(config.LAddEpsilon)
	safeGammaBound := new(big.Int).Mul(new(big.Int).Lsh(big1, safeGammaBits), pedN)
	gamma, err := utils.RandomAbsoluteRangeInt(safeGammaBound)
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

	msgs := append(utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), n0.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), C.Bytes(), S.Bytes(), A.Bytes(), D.Bytes()), msgG, msgX, msgY)
	e, counter, err := GetE(KnowExponentAndPaillierEncryption, curveN, msgs...)
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
		Counter: counter,
		S:       S.Bytes(),
		A:       A.Bytes(),
		Y:       msgY,
		D:       D.Bytes(),
		Z1:      z1.String(),
		Z2:      z2.Bytes(),
		Z3:      z3.String(),
	}, nil
}

func (msg *LogStarMessage) Verify(config *CurveConfig, ssidInfo []byte, C, n0 *big.Int, ped *PederssenOpenParameter, X *pt.ECPoint, G *pt.ECPoint) error {
	n0Square := new(big.Int).Exp(n0, big2, nil)
	curveN := G.GetCurve().Params().N
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()

	S := new(big.Int).SetBytes(msg.S)
	if err := utils.InRange(S, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(S, pedN) {
		return ErrVerifyFailure
	}

	A := new(big.Int).SetBytes(msg.A)
	if err := utils.InRange(A, big0, n0Square); err != nil {
		return err
	}

	if !utils.IsRelativePrime(A, n0Square) {
		return ErrVerifyFailure
	}

	D := new(big.Int).SetBytes(msg.D)
	if err := utils.InRange(D, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(D, pedN) {
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
	if err := utils.InRange(z2, big0, n0); err != nil {
		return err
	}
	if !utils.IsRelativePrime(z2, n0) {
		return ErrVerifyFailure
	}

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

	msgs := append(utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), n0.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), C.Bytes(), S.Bytes(), A.Bytes(), D.Bytes()), msgG, msgX, msg.Y)
	e, expectedCounter, err := GetE(KnowExponentAndPaillierEncryption, curveN, msgs...)
	if err != nil {
		return err
	}
	if expectedCounter != msg.Counter {
		return ErrVerifyFailure
	}

	eBits := uint(curveN.BitLen())
	xBits := uint(config.L)
	safeAlphaBits := xBits + eBits + uint(config.LAddEpsilon)

	// Check：z1 ∈ ±2^{safeAlphaBits+1} (add more 1 bit)
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big1, safeAlphaBits+1)) > 0 {
		return ErrVerifyFailure
	}

	// Check z1*G = Y + e*X
	YXexpe := X.ScalarMult(e)
	YXexpe, err = YXexpe.Add(Y)
	if err != nil {
		return err
	}
	gz1 := G.ScalarMult(z1)
	if !gz1.Equal(YXexpe) {
		return ErrVerifyFailure
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

	// Check s^{z1}t^{z3} = D·S^e mod Nˆ
	sz1tz3 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z3, pedN))
	sz1tz3.Mod(sz1tz3, pedN)
	DSexpe := new(big.Int).Mul(D, new(big.Int).Exp(S, e, pedN))
	DSexpe.Mod(DSexpe, pedN)
	if sz1tz3.Cmp(DSexpe) != 0 {
		return ErrVerifyFailure
	}

	return nil
}
