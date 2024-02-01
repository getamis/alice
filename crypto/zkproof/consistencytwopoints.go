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
	"math/big"

	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
)

/*
	Notations:
	- secret keys: σ,l
	- public points: R and H
	- field Order: p

	Alice(i.e. Prover) has two secret integers σ and l and two public points R and H .
	1. Check σ,l ∈ [0, p−1].
	2. Randomly choose a,b ∈ [1, p−1] and compute A := a·R and B := a·G + b·H.
	3. Compute c = H(G,A,B,R,H).
	4. Compute u := a + cσ mod p and t := b + c·l mod p.
	The proof includes u, t, A, B.

	Step 2: The verifier verifies
	1. Check u,t ∈ [0, p-1].
	2: Compute c = H(G,A,B,R,H).
	3: Check t·R = A + c·S and t·G + u·H = B + c·T.
	If the result true accept, otherwise reject.
*/
type consistencyTwoPointsMessage struct {
	u []byte
	t []byte
	A *ecpointgrouplaw.EcPointMessage
	B *ecpointgrouplaw.EcPointMessage
	S *ecpointgrouplaw.EcPointMessage
	T *ecpointgrouplaw.EcPointMessage
}

func NewConsistencyTwoPoints(sigma, ell *big.Int, R, H *pt.ECPoint) (*consistencyTwoPointsMessage, error) {
	fieldOrder := R.GetCurve().Params().N
	// Check σ,l ∈ [0, p−1].
	err := utils.InRange(sigma, big0, fieldOrder)
	if err != nil {
		return nil, err
	}
	err = utils.InRange(ell, big0, fieldOrder)
	if err != nil {
		return nil, err
	}

	// Randomly choose a,b ∈ [1, p−1] and compute A := a·R and B := a·G + b·H.
	a, err := utils.RandomPositiveInt(fieldOrder)
	if err != nil {
		return nil, err
	}
	b, err := utils.RandomPositiveInt(fieldOrder)
	if err != nil {
		return nil, err
	}
	A := R.ScalarMult(a)
	B := pt.ScalarBaseMult(R.GetCurve(), a)
	bH := H.ScalarMult(b)
	B, err = B.Add(bH)
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

	// Compute c = H(G,A,B,R,H).
	c := big.NewInt(1)

	// Compute u := a + cσ mod p and t := b + c·l mod p.
	u := new(big.Int).Mul(c, sigma)
	u = u.Add(u, a)

	t := new(big.Int).Mul(c, ell)
	t = t.Add(t, b)

	proof := &consistencyTwoPointsMessage{
		u: u.Bytes(),
		t: t.Bytes(),
		A: msgA,
		B: msgB,
	}
	err = proof.Verify(R, H)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func (s *consistencyTwoPointsMessage) Verify(R, H *pt.ECPoint) error {
	A, err := s.A.ToPoint()
	if err != nil {
		return err
	}
	fieldOrder := A.GetCurve().Params().N

	// Check u,t ∈ [0, p-1].
	u := new(big.Int).SetBytes(s.u)
	err = utils.InRange(u, big0, fieldOrder)
	if err != nil {
		return err
	}
	t := new(big.Int).SetBytes(s.t)
	err = utils.InRange(t, big0, fieldOrder)
	if err != nil {
		return err
	}

	// Compute c = H(G,A,B,R,H).
	c := big.NewInt(1)
	// Check t·R = A + c·S and t·G + u·H = B + c·T.
	S, err := s.S.ToPoint()
	if err != nil {
		return err
	}
	if !S.IsSameCurve(A) {
		return ErrDifferentCurves
	}
	if !S.IsSameCurve(R) {
		return ErrDifferentCurves
	}
	aAddcS := S.ScalarMult(c)
	aAddcS, err = A.Add(aAddcS)
	if err != nil {
		return err
	}
	tR := R.ScalarMult(t)
	if !tR.Equal(aAddcS) {
		return ErrVerifyFailure
	}

	T, err := s.T.ToPoint()
	if err != nil {
		return err
	}
	B, err := s.B.ToPoint()
	if err != nil {
		return err
	}
	if !T.IsSameCurve(B) {
		return ErrDifferentCurves
	}
	if !T.IsSameCurve(H) {
		return ErrDifferentCurves
	}

	BaddCT := T.ScalarMult(c)
	BaddCT, err = BaddCT.Add(B)
	tGAdduH := H.ScalarMult(u)
	tG := pt.ScalarBaseMult(T.GetCurve(), t)
	tGAdduH, err = tGAdduH.Add(tG)
	if !tGAdduH.IsSameCurve(BaddCT) {
		return ErrDifferentCurves
	}
	return nil
}
