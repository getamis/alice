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
	3: Check u·R = A + c·S and u·G + t·H = B + c·T.
	If the result true accept, otherwise reject.
*/

func NewConsistencyTwoPoints(sigma *big.Int, ell *big.Int, R, H, S, T *pt.ECPoint) (*ConsistencyTwoPointsMessage, error) {
	curve := R.GetCurve()
	fieldOrder := curve.Params().N

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
	B := pt.ScalarBaseMult(curve, a)
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
	G := pt.NewBase(curve)
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgR, err := R.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgH, err := H.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	// Compute c = H(G,A,B,R,H).
	c, salt, err := utils.HashProtosRejectSampling(fieldOrder, msgG, msgA, msgB, msgR, msgH)
	if err != nil {
		return nil, err
	}

	// Compute u := a + cσ mod p and t := b + c·l mod p.
	u := new(big.Int).Mul(c, sigma)
	u = u.Add(u, a)
	u.Mod(u, fieldOrder)

	t := new(big.Int).Mul(c, ell)
	t = t.Add(t, b)
	t.Mod(t, fieldOrder)

	proof := &ConsistencyTwoPointsMessage{
		Salt: salt,
		U:    u.Bytes(),
		T:    t.Bytes(),
		A:    msgA,
		B:    msgB,
	}
	err = proof.Verify(R, H, S, T)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func (s *ConsistencyTwoPointsMessage) Verify(R, H, S, T *pt.ECPoint) error {
	curve := R.GetCurve()
	A, err := s.A.ToPoint()
	if err != nil {
		return err
	}
	fieldOrder := curve.Params().N

	// Check u,t ∈ [0, p-1].
	u := new(big.Int).SetBytes(s.U)
	err = utils.InRange(u, big0, fieldOrder)
	if err != nil {
		return err
	}
	t := new(big.Int).SetBytes(s.T)
	err = utils.InRange(t, big0, fieldOrder)
	if err != nil {
		return err
	}

	// Compute c = H(G,A,B,R,H).
	G := pt.NewBase(curve)
	msgG, err := G.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgR, err := R.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgH, err := H.ToEcPointMessage()
	if err != nil {
		return err
	}
	c, err := utils.HashProtosToInt(s.Salt, msgG, s.A, s.B, msgR, msgH)
	if err != nil {
		return err
	}

	// Check u·R = A + c·S.
	aAddcS := S.ScalarMult(c)
	aAddcS, err = A.Add(aAddcS)
	if err != nil {
		return err
	}
	uR := R.ScalarMult(u)
	if !uR.Equal(aAddcS) {
		return ErrVerifyFailure
	}

	// Check u·G + t·H = B + c·T.
	B, err := s.B.ToPoint()
	if err != nil {
		return err
	}
	BaddCT := T.ScalarMult(c)
	BaddCT, err = BaddCT.Add(B)
	if err != nil {
		return err
	}
	uGAddtH := H.ScalarMult(t)
	uG := G.ScalarMult(u)
	uGAddtH, err = uGAddtH.Add(uG)
	if err != nil {
		return err
	}
	if !uGAddtH.Equal(BaddCT) {
		return ErrVerifyFailure
	}
	return nil
}
