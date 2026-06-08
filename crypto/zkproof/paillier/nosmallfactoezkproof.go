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

const NoSmallFactor = "AMIS-Alice-NoSmallFactor-ZK-v1.0-"

func NewNoSmallFactorMessage(config *CurveConfig, ssidInfo, rho []byte, p *big.Int, q *big.Int, n *big.Int, ped *PederssenOpenParameter) (*NoSmallFactorMessage, error) {
	sqrtN := new(big.Int).Sqrt(n)
	groupOrder := config.Curve.Params().N
	twoellAddepsionSqrtN := new(big.Int).Lsh(sqrtN, uint(config.LAddEpsilon))
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()
	// Sample α,β in ±2^{l+ε}·N0^1/2
	alpha, err := utils.RandomAbsoluteRangeInt(twoellAddepsionSqrtN)
	if err != nil {
		return nil, err
	}
	beta, err := utils.RandomAbsoluteRangeInt(twoellAddepsionSqrtN)
	if err != nil {
		return nil, err
	}
	twoellpedn := new(big.Int).Mul(config.TwoExpL, pedN)
	// Sample μ,ν in ±2^l·N0·Nˆ
	mu, err := utils.RandomAbsoluteRangeInt(twoellpedn)
	if err != nil {
		return nil, err
	}
	v, err := utils.RandomAbsoluteRangeInt(twoellpedn)
	if err != nil {
		return nil, err
	}
	// Sample ρ in ±2^l ·N0 ·Nˆ
	sigma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(twoellpedn, n))
	if err != nil {
		return nil, err
	}
	twoellAddepsionpedn := new(big.Int).Mul(config.TwoExpLAddepsilon, pedN)
	// Sample r in ±2^{l+ε} ·N0 ·Nˆ
	r, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(twoellAddepsionpedn, n))
	if err != nil {
		return nil, err
	}
	// Sample x, y in ±2^{l+ε} ·N0 ·Nˆ
	x, err := utils.RandomAbsoluteRangeInt(twoellAddepsionpedn)
	if err != nil {
		return nil, err
	}
	y, err := utils.RandomAbsoluteRangeInt(twoellAddepsionpedn)
	if err != nil {
		return nil, err
	}
	// P = s^p*t^μ,Q=s^q*t^ν mod Nˆ.
	P := new(big.Int).Mul(new(big.Int).Exp(peds, p, pedN), new(big.Int).Exp(pedt, mu, pedN))
	P.Mod(P, pedN)
	Q := new(big.Int).Mul(new(big.Int).Exp(peds, q, pedN), new(big.Int).Exp(pedt, v, pedN))
	Q.Mod(Q, pedN)
	// A=s^α*t^x mod Nˆ.
	A := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, x, pedN))
	A.Mod(A, pedN)
	// B=s^β*t^y mod Nˆ.
	B := new(big.Int).Mul(new(big.Int).Exp(peds, beta, pedN), new(big.Int).Exp(pedt, y, pedN))
	B.Mod(B, pedN)
	// T = Q^α*t^r mod Nˆ.
	T := new(big.Int).Mul(new(big.Int).Exp(Q, alpha, pedN), new(big.Int).Exp(pedt, r, pedN))
	T.Mod(T, pedN)
	e, counter, err := GetE(NoSmallFactor, groupOrder, utils.GetAnyMsg(ssidInfo, rho, n.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), P.Bytes(), Q.Bytes(), A.Bytes(), B.Bytes(), T.Bytes(), []byte(sigma.String()))...)
	if err != nil {
		return nil, err
	}
	// z1 = α + ep, z2 =β+eq, w1 = x+eμ, w2 =y+eν, and v = r+eρ ˆ.
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, p))
	z2 := new(big.Int).Add(beta, new(big.Int).Mul(e, q))
	w1 := new(big.Int).Add(x, new(big.Int).Mul(e, mu))
	w2 := new(big.Int).Add(y, new(big.Int).Mul(e, v))
	vletter := new(big.Int).Add(r, new(big.Int).Mul(e, new(big.Int).Sub(sigma, new(big.Int).Mul(v, p))))

	return &NoSmallFactorMessage{
		Counter: counter,
		P:       P.Bytes(),
		Q:       Q.Bytes(),
		A:       A.Bytes(),
		B:       B.Bytes(),
		T:       T.Bytes(),
		Sigma:   sigma.String(),
		Z1:      z1.String(),
		Z2:      z2.String(),
		W1:      w1.String(),
		W2:      w2.String(),
		Vletter: vletter.String(),
	}, nil
}

func (msg *NoSmallFactorMessage) Verify(config *CurveConfig, ssidInfo, rho []byte, n *big.Int, ped *PederssenOpenParameter) error {
	if n.Cmp(big0) <= 0 || n.Bit(0) == 0 {
		return ErrInvalidInput
	}
	if n.BitLen() < SAFESECURITYLEVEL {
		return ErrInvalidInput
	}

	groupOrder := config.Curve.Params().N
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()

	P := new(big.Int).SetBytes(msg.P)
	if err := utils.InRange(P, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(P, pedN) {
		return ErrVerifyFailure
	}

	Q := new(big.Int).SetBytes(msg.Q)
	if err := utils.InRange(Q, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(Q, pedN) {
		return ErrVerifyFailure
	}

	A := new(big.Int).SetBytes(msg.A)
	if err := utils.InRange(A, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(A, pedN) {
		return ErrVerifyFailure
	}

	B := new(big.Int).SetBytes(msg.B)
	if err := utils.InRange(B, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(B, pedN) {
		return ErrVerifyFailure
	}

	T := new(big.Int).SetBytes(msg.T)
	if err := utils.InRange(T, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(T, pedN) {
		return ErrVerifyFailure
	}

	sigma, ok := new(big.Int).SetString(msg.Sigma, 10)
	if !ok {
		return ErrInvalidInput
	}
	z1, ok := new(big.Int).SetString(msg.Z1, 10)
	if !ok {
		return ErrInvalidInput
	}
	z2, ok := new(big.Int).SetString(msg.Z2, 10)
	if !ok {
		return ErrInvalidInput
	}
	w1, ok := new(big.Int).SetString(msg.W1, 10)
	if !ok {
		return ErrInvalidInput
	}
	w2, ok := new(big.Int).SetString(msg.W2, 10)
	if !ok {
		return ErrInvalidInput
	}
	v, ok := new(big.Int).SetString(msg.Vletter, 10)
	if !ok {
		return ErrInvalidInput
	}

	// Defensive anti-DoS check: Restrict w1, w2, and v to prevent CPU exhaustion via giant exponents.
	// Max theoretical bits for w1, w2 is roughly (l + epsilon + pedN.BitLen + 2) bits.
	maxWBitLen := uint(config.LAddEpsilon) + uint(pedN.BitLen()) + 2
	if uint(w1.BitLen()) > maxWBitLen || uint(w2.BitLen()) > maxWBitLen {
		return ErrVerifyFailure
	}

	// Max theoretical bits for vletter is roughly (l + epsilon + pedN.BitLen + n.BitLen + 2) bits.
	maxVBitLen := maxWBitLen + uint(n.BitLen())
	if uint(v.BitLen()) > maxVBitLen {
		return ErrVerifyFailure
	}

	// Compute R = s^n * t^sigma mod N_hat
	R := new(big.Int).Mul(new(big.Int).Exp(peds, n, pedN), new(big.Int).Exp(pedt, sigma, pedN))
	R.Mod(R, pedN)

	msgs := utils.GetAnyMsg(ssidInfo, rho, n.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), P.Bytes(), Q.Bytes(), A.Bytes(), B.Bytes(), T.Bytes(), []byte(sigma.String()))
	e, expectedCounter, err := GetE(NoSmallFactor, groupOrder, msgs...)
	if err != nil {
		return err
	}
	if expectedCounter != msg.Counter {
		return ErrVerifyFailure
	}

	sqrtN := new(big.Int).Sqrt(n)
	upBd := new(big.Int).Lsh(sqrtN, uint(config.LAddEpsilon))

	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(upBd) > 0 {
		return ErrVerifyFailure
	}
	absZ2 := new(big.Int).Abs(z2)
	if absZ2.Cmp(upBd) > 0 {
		return ErrVerifyFailure
	}

	// Check s^{z1} * t^{w1} = A · P^e mod N_hat
	ADexpe := new(big.Int).Mul(A, new(big.Int).Exp(P, e, pedN))
	ADexpe.Mod(ADexpe, pedN)
	compare := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, w1, pedN))
	compare.Mod(compare, pedN)
	if compare.Cmp(ADexpe) != 0 {
		return ErrVerifyFailure
	}

	// Check s^{z2} * t^{w2} = B · Q^e mod N_hat
	BQexpe := new(big.Int).Mul(B, new(big.Int).Exp(Q, e, pedN))
	BQexpe.Mod(BQexpe, pedN)
	compare = new(big.Int).Mul(new(big.Int).Exp(peds, z2, pedN), new(big.Int).Exp(pedt, w2, pedN))
	compare.Mod(compare, pedN)
	if compare.Cmp(BQexpe) != 0 {
		return ErrVerifyFailure
	}

	// Check Q^{z1} * t^v = T · R^e mod N_hat
	TRexpe := new(big.Int).Mul(T, new(big.Int).Exp(R, e, pedN))
	TRexpe.Mod(TRexpe, pedN)
	compare = new(big.Int).Mul(new(big.Int).Exp(Q, z1, pedN), new(big.Int).Exp(pedt, v, pedN))
	compare.Mod(compare, pedN)
	if compare.Cmp(TRexpe) != 0 {
		return ErrVerifyFailure
	}

	return nil
}
