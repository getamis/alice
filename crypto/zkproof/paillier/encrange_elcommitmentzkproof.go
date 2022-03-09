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

func NewEncryptRangeWithELMessage(config *CurveConfig, ssidInfo []byte, x, rho, a, b, ciphertext, N *big.Int, A, B, X *pt.ECPoint, pedersenN *big.Int, pedersenS *big.Int, pedersenT *big.Int) (*EncElgMessage, error) {
	curve := A.GetCurve()
	curveN := curve.Params().N
	G := pt.NewBase(curve)

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
	// Sample r in Z_{N}^ast.
	r, err := utils.RandomCoprimeInt(N)
	if err != nil {
		return nil, err
	}
	// Sample beta in F_q
	beta, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}
	// Sample γ in ± 2^{l+ε}·Nˆ.
	gamma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpLAddepsilon, pedersenN))
	if err != nil {
		return nil, err
	}

	NSquare := new(big.Int).Mul(N, N)
	// S = s^x*t^μ mod Nˆ
	S := new(big.Int).Mul(new(big.Int).Exp(pedersenS, x, pedersenN), new(big.Int).Exp(pedersenT, mu, pedersenN))
	S.Mod(S, pedersenN)
	// D = (1+N_0)^α·r^{N_0} mod N_0^2
	D := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, N), alpha, NSquare), new(big.Int).Exp(r, N, NSquare))
	D.Mod(D, NSquare)
	// Y=beta*A+alpha*G,Z=beta*G
	Y := A.ScalarMult(beta)
	Y, err = Y.Add(G.ScalarMult(alpha))
	if err != nil {
		return nil, err
	}
	Z := G.ScalarMult(beta)

	// T = s^α*t^γ mod Nˆ
	T := new(big.Int).Mul(new(big.Int).Exp(pedersenS, alpha, pedersenN), new(big.Int).Exp(pedersenT, gamma, pedersenN))
	T.Mod(T, pedersenN)

	msgY, err := Y.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgX, err := X.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgZ, err := Z.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgA, err := A.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgB, err := B.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	msgs := append(utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), ciphertext.Bytes(), S.Bytes(), T.Bytes(), D.Bytes(), N.Bytes()), msgY, msgZ, msgA, msgB, msgG, msgX)
	e, salt, err := GetE(curveN, msgs...)
	if err != nil {
		return nil, err
	}
	// z1 = α+ek
	z1 := new(big.Int).Mul(e, x)
	z1.Add(z1, alpha)
	// w = β+eb mod q
	w := new(big.Int).Mul(e, b)
	w.Add(w, beta)
	w.Mod(w, curveN)
	// z2 = r·ρ^e mod N
	z2 := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, N))
	z2.Mod(z2, N)
	// z3 =γ+eμ
	z3 := new(big.Int).Mul(e, mu)
	z3.Add(z3, gamma)
	return &EncElgMessage{
		Salt: salt,
		S:    S.Bytes(),
		T:    T.Bytes(),
		D:    D.Bytes(),
		Y:    msgY,
		Z:    msgZ,
		Z1:   z1.String(),
		Z2:   z2.Bytes(),
		W:    w.Bytes(),
		Z3:   z3.String(),
	}, nil
}

// TODO: check range of message elements
func (msg *EncElgMessage) Verify(config *CurveConfig, ssidInfo []byte, ciphertext, N *big.Int, A, B, X *pt.ECPoint, pedersenN, pedersenS, pedersenT *big.Int) error {
	curve := A.GetCurve()
	curveN := curve.Params().N
	G := pt.NewBase(curve)
	S := new(big.Int).SetBytes(msg.S)
	T := new(big.Int).SetBytes(msg.T)
	D := new(big.Int).SetBytes(msg.D)
	Y, err := msg.Y.ToPoint()
	if err != nil {
		return err
	}
	Z, err := msg.Z.ToPoint()
	if err != nil {
		return err
	}
	W := new(big.Int).SetBytes(msg.W)
	err = utils.InRange(W, big0, curveN)
	if err != nil {
		return err
	}

	z1, _ := new(big.Int).SetString(msg.Z1, 10)
	z2 := new(big.Int).SetBytes(msg.Z2)
	err = utils.InRange(z2, big0, N)
	if err != nil {
		return err
	}

	z3, _ := new(big.Int).SetString(msg.Z3, 10)
	msgA, err := A.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgB, err := B.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgX, err := X.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return err
	}
	NSaure := new(big.Int).Mul(N, N)

	msgs := append(utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), ciphertext.Bytes(), S.Bytes(), T.Bytes(), D.Bytes(), N.Bytes()), msg.Y, msg.Z, msgA, msgB, msgG, msgX)
	seed, err := utils.HashProtos(msg.Salt, msgs...)
	if err != nil {
		return err
	}
	e := utils.RandomAbsoluteRangeIntBySeed(seed, curveN)
	err = utils.InRange(e, new(big.Int).Neg(curveN), new(big.Int).Add(big1, curveN))
	if err != nil {
		return err
	}

	// Check (1+N)^{z1} ·z_2^{N_0} =D·C^e mod N_0^2.
	DCexpe := new(big.Int).Mul(D, new(big.Int).Exp(ciphertext, e, NSaure))
	DCexpe.Mod(DCexpe, NSaure)
	temp := new(big.Int).Add(big1, N)
	temp.Exp(temp, z1, NSaure)
	compare := new(big.Int).Exp(z2, N, NSaure)
	compare.Mul(compare, temp)
	compare.Mod(compare, NSaure)
	if compare.Cmp(DCexpe) != 0 {
		return ErrVerifyFailure
	}

	// w*A+z1*G = Y + e*X
	awAddz1G := A.ScalarMult(W)
	awAddz1G, err = awAddz1G.Add(G.ScalarMult(z1))
	if err != nil {
		return err
	}
	comparePoint := X.ScalarMult(e)
	comparePoint, err = comparePoint.Add(Y)
	if err != nil {
		return err
	}
	if !comparePoint.Equal(awAddz1G) {
		return ErrVerifyFailure
	}
	// w*g = Z+e*B
	wG := G.ScalarMult(W)
	comparePoint = B.ScalarMult(e)
	comparePoint, err = comparePoint.Add(Z)
	if err != nil {
		return err
	}
	if !wG.Equal(comparePoint) {
		return ErrVerifyFailure
	}

	// Check s^{z1}*t^{z3} =T·S^e mod Nˆ
	TSexpe := new(big.Int).Mul(T, new(big.Int).Exp(S, e, pedersenN))
	TSexpe.Mod(TSexpe, pedersenN)
	compare = new(big.Int).Mul(new(big.Int).Exp(pedersenS, z1, pedersenN), new(big.Int).Exp(pedersenT, z3, pedersenN))
	compare.Mod(compare, pedersenN)
	if TSexpe.Cmp(compare) != 0 {
		return ErrVerifyFailure
	}

	// Check z1 ∈ ±2^{l+ε}.
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big2, uint(config.LAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	return nil
}
