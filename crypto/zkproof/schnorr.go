// Copyright © 2020 AMIS Technologies
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

package zkproof

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
)

var (
	// ErrDifferentCurves is returned if the two points are in different curves
	ErrDifferentCurves = errors.New("different curves")
)

/*
	Notations:
	- secret keys: a1, a2
	- public key: V
	- fix point: R
	- base point: G

	Alice(i.e. Prover) chooses secret keys: a1, a2 in [1,p-1] and broadcast the public key: V := a1G + a2R.
	Through the following protocol, Bob(i.e. Verifier) can be convinced that Alice knows a1, a2, but Bob does not
	learn a1, a2 in this protocol. We use Fiat–Shamir heuristic to get the following Schnorr protocol.

	Step 1:
	- The prover randomly chooses two numbers m, n in [1, p-1] and sends alpha := m*G + n*R to the verifier.
	- The prover computes c:=H(G,alpha,V,R).
	- The prover computes  u := m + c*a1 mod p and t := n + c*a2 mod p. The resulting proof is the (u,t, alpha)
	Step 2: The verifier verifies t*R + u*G = alpha +c*V, and u, t in [0, p-1]. If the result true accept, otherwise reject.
	Remark: If R is the identity element(i.e. R = (nil,nil)) and t = 0, then the above protocol reduces to the standard Schnorr protocol.
*/

func NewBaseSchorrMessage(curve elliptic.Curve, a1 *big.Int) (*SchnorrProofMessage, error) {
	base := pt.NewBase(curve)
	return NewSchorrMessage(a1, big0, base)
}

func NewSchorrMessage(a1 *big.Int, a2 *big.Int, R *pt.ECPoint) (*SchnorrProofMessage, error) {
	msgR, err := R.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	curve := R.GetCurve()
	fieldOrder := curve.Params().N

	// Ensure a1, a2 in the range
	err = utils.InRange(a1, big0, fieldOrder)
	if err != nil {
		return nil, err
	}
	err = utils.InRange(a2, big0, fieldOrder)
	if err != nil {
		return nil, err
	}

	// Calculate V = a1*G + a2*R
	G := pt.NewBase(curve)
	a1G := pt.ScalarBaseMult(curve, a1)
	a2R := R.ScalarMult(a2)
	V, err := a1G.Add(a2R)
	if err != nil {
		return nil, err
	}
	msgV, err := V.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	// Calculate alpha = mG + nR
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	m, err := utils.RandomInt(fieldOrder)
	if err != nil {
		return nil, err
	}
	mG := pt.ScalarBaseMult(curve, m)
	n, err := utils.RandomInt(fieldOrder)
	if err != nil {
		return nil, err
	}
	nR := R.ScalarMult(n)
	alpha, err := mG.Add(nR)
	if err != nil {
		return nil, err
	}
	msgAlpha, err := alpha.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	// Compute c
	salt, err := utils.GenRandomBytes(utils.SaltSize)
	if err != nil {
		return nil, err
	}
	c, err := utils.HashProtosWithFieldOrder(salt, fieldOrder, msgG, msgV, msgR, msgAlpha)
	if err != nil {
		return nil, err
	}

	// Calculate u := m + c*a1 mod p
	u := new(big.Int).Mul(a1, c)
	u = new(big.Int).Add(m, u)
	u = new(big.Int).Mod(u, fieldOrder)

	// Calculate t := n + c*a2 mod p
	t := new(big.Int).Mul(a2, c)
	t = new(big.Int).Add(n, t)
	t = new(big.Int).Mod(t, fieldOrder)

	// Build and verify message again
	msg := &SchnorrProofMessage{
		Salt:  salt,
		V:     msgV,
		Alpha: msgAlpha,
		U:     u.Bytes(),
		T:     t.Bytes(),
	}
	err = msg.Verify(R)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (s *SchnorrProofMessage) Verify(R *pt.ECPoint) error {
	curve := R.GetCurve()
	fieldOrder := curve.Params().N

	// Ensure U and T in the range
	u := new(big.Int).SetBytes(s.U)
	err := utils.InRange(u, big0, fieldOrder)
	if err != nil {
		return err
	}
	t := new(big.Int).SetBytes(s.T)
	err = utils.InRange(t, big0, fieldOrder)
	if err != nil {
		return err
	}

	// Enure messages are correct
	V, err := s.V.ToPoint()
	if err != nil {
		return err
	}
	if !V.IsSameCurve(R) {
		return ErrDifferentCurves
	}
	alpha, err := s.Alpha.ToPoint()
	if err != nil {
		return err
	}
	if !alpha.IsSameCurve(R) {
		return ErrDifferentCurves
	}

	G := pt.NewBase(curve)
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgR, err := R.ToEcPointMessage()
	if err != nil {
		return err
	}

	// Calculate t*R + u*G
	p1 := pt.ScalarBaseMult(curve, u)
	p2 := R.ScalarMult(t)
	result1, err := p1.Add(p2)
	if err != nil {
		return err
	}

	// Calculate alpha + c*V
	c, err := utils.HashProtosWithFieldOrder(s.Salt, fieldOrder, msgG, s.V, msgR, s.Alpha)
	if err != nil {
		return err
	}
	v1 := V.ScalarMult(c)
	result2, err := v1.Add(alpha)
	if err != nil {
		return err
	}

	// Expect t*R + u*G = alpha + c*V
	if !result1.Equal(result2) {
		return ErrVerifyFailure
	}
	return nil
}
