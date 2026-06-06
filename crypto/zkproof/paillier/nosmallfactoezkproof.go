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
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()

	eBits := uint(groupOrder.BitLen())
	lBits := uint(config.L)
	epsilonBits := uint(config.LAddEpsilon) - lBits

	// α, β (alpha, beta)  = len(sqrtN) + len(e) + epsilon
	safeAlphaBits := uint(sqrtN.BitLen()) + eBits + epsilonBits
	safeAlphaBound := new(big.Int).Lsh(big1, safeAlphaBits)
	alpha, err := utils.RandomAbsoluteRangeInt(safeAlphaBound)
	if err != nil {
		return nil, err
	}
	beta, err := utils.RandomAbsoluteRangeInt(safeAlphaBound)
	if err != nil {
		return nil, err
	}

	// μ, ν (mu, v) (2^L * pedN)
	muBound := new(big.Int).Lsh(pedN, lBits)
	mu, err := utils.RandomAbsoluteRangeInt(muBound)
	if err != nil {
		return nil, err
	}
	v, err := utils.RandomAbsoluteRangeInt(muBound)
	if err != nil {
		return nil, err
	}

	// ρ (sigma) (2^L * pedN * n)
	sigmaBound := new(big.Int).Mul(muBound, n)
	sigma, err := utils.RandomAbsoluteRangeInt(sigmaBound)
	if err != nil {
		return nil, err
	}

	// x, y blinds e * mu, len(muBound) + len(e) + epsilon
	safeXBits := lBits + uint(pedN.BitLen()) + eBits + epsilonBits
	safeXBound := new(big.Int).Lsh(big1, safeXBits)
	x, err := utils.RandomAbsoluteRangeInt(safeXBound)
	if err != nil {
		return nil, err
	}
	y, err := utils.RandomAbsoluteRangeInt(safeXBound)
	if err != nil {
		return nil, err
	}

	// r blinds e * sigma, len(sigmaBound) + len(e) + epsilon
	safeRBits := lBits + uint(pedN.BitLen()) + uint(n.BitLen()) + eBits + epsilonBits
	safeRBound := new(big.Int).Lsh(big1, safeRBits)
	r, err := utils.RandomAbsoluteRangeInt(safeRBound)
	if err != nil {
		return nil, err
	}

	// P = s^p*t^μ, Q=s^q*t^ν mod Nˆ.
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
	R := new(big.Int).Mul(new(big.Int).Exp(peds, n, pedN), new(big.Int).Exp(pedt, sigma, pedN))
	R.Mod(R, pedN)

	e, counter, err := GetE(NoSmallFactor, groupOrder, utils.GetAnyMsg(ssidInfo, rho, n.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), P.Bytes(), Q.Bytes(), A.Bytes(), B.Bytes(), T.Bytes(), R.Bytes())...)
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

	// Compute R = s^n * t^sigma mod N_hat
	R := new(big.Int).Mul(new(big.Int).Exp(peds, n, pedN), new(big.Int).Exp(pedt, sigma, pedN))
	R.Mod(R, pedN)

	msgs := utils.GetAnyMsg(ssidInfo, rho, n.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), P.Bytes(), Q.Bytes(), A.Bytes(), B.Bytes(), T.Bytes(), R.Bytes())
	e, expectedCounter, err := GetE(NoSmallFactor, groupOrder, msgs...)
	if err != nil {
		return err
	}
	if expectedCounter != msg.Counter {
		return ErrVerifyFailure
	}

	eBits := uint(groupOrder.BitLen())
	lBits := uint(config.L)
	epsilonBits := uint(config.LAddEpsilon) - lBits

	sqrtN := new(big.Int).Sqrt(n)
	safeAlphaBits := uint(sqrtN.BitLen()) + eBits + epsilonBits
	upBd := new(big.Int).Lsh(big1, safeAlphaBits+1)

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
