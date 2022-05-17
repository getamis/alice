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

func NewELog(config *CurveConfig, ssidInfo []byte, y, lambda *big.Int, L, M, X, Y, h *pt.ECPoint) (*ELogMessage, error) {
	curveN := L.GetCurve().Params().N
	G := pt.NewBase(L.GetCurve())

	// Sample α,m in Fq.
	alpha, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}
	m, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}

	// Compute A= alpha*G, N = m*G+alpha*X and B= m*h
	A := G.ScalarMult(alpha)
	N := G.ScalarMult(m)
	N, err = N.Add(X.ScalarMult(alpha))
	if err != nil {
		return nil, err
	}
	B := h.ScalarMult(m)

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
	msgA, err := A.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgB, err := B.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgN, err := N.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgL, err := L.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgM, err := M.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgh, err := h.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	msgs := append(utils.GetAnyMsg(ssidInfo), msgA, msgB, msgL, msgM, msgX, msgY, msgh, msgN, msgG)
	e, salt, err := GetE(curveN, msgs...)
	if err != nil {
		return nil, err
	}
	// z = α+eλ
	z := new(big.Int).Add(alpha, new(big.Int).Mul(e, lambda))
	z.Mod(z, curveN)
	// u = m+ey mod q
	u := new(big.Int).Add(m, new(big.Int).Mul(e, y))
	u.Mod(u, curveN)

	return &ELogMessage{
		Salt: salt,
		A:    msgA,
		B:    msgB,
		N:    msgN,
		Z:    z.Bytes(),
		U:    u.Bytes(),
	}, nil
}

func (msg *ELogMessage) Verify(config *CurveConfig, ssidInfo []byte, L, M, X, Y, h *pt.ECPoint) error {
	curveN := L.GetCurve().Params().N
	G := pt.NewBase(L.GetCurve())

	z := new(big.Int).SetBytes(msg.Z)
	err := utils.InRange(z, big0, curveN)
	if err != nil {
		return err
	}
	u := new(big.Int).SetBytes(msg.U)
	err = utils.InRange(u, big0, curveN)
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
	msgY, err := Y.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgL, err := L.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgM, err := M.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgh, err := h.ToEcPointMessage()
	if err != nil {
		return err
	}

	msgs := append(utils.GetAnyMsg(ssidInfo), msg.A, msg.B, msgL, msgM, msgX, msgY, msgh, msg.N, msgG)
	seed, err := utils.HashProtos(msg.Salt, msgs...)
	if err != nil {
		return err
	}

	e := utils.RandomAbsoluteRangeIntBySeed(msg.Salt, seed, curveN)
	err = utils.InRange(e, new(big.Int).Neg(curveN), new(big.Int).Add(big1, curveN))
	if err != nil {
		return err
	}
	A, err := msg.A.ToPoint()
	if err != nil {
		return err
	}
	B, err := msg.B.ToPoint()
	if err != nil {
		return err
	}
	N, err := msg.N.ToPoint()
	if err != nil {
		return err
	}

	// Check z*G = A+ e*L.
	zG := G.ScalarMult(z)
	AaddeL := L.ScalarMult(e)
	AaddeL, err = AaddeL.Add(A)
	if err != nil {
		return err
	}
	if !zG.Equal(AaddeL) {
		return ErrVerifyFailure
	}

	// Check u*G + z*X = N + e*M
	uGAddzX := G.ScalarMult(u)
	uGAddzX, err = uGAddzX.Add(X.ScalarMult(z))
	if err != nil {
		return err
	}
	NAddeM := M.ScalarMult(e)
	NAddeM, err = NAddeM.Add(N)
	if err != nil {
		return err
	}
	if !NAddeM.Equal(uGAddzX) {
		return ErrVerifyFailure
	}

	// u*h = B+e*Y
	uh := h.ScalarMult(u)
	BAddeY := Y.ScalarMult(e)
	BAddeY, err = BAddeY.Add(B)
	if err != nil {
		return err
	}

	if !uh.Equal(BAddeY) {
		return ErrVerifyFailure
	}
	return nil
}
