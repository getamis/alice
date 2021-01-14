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
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
)

/*
	Notations:
	- secret key: x
	- base point: G
	- public key: x*G

	Alice(i.e. Prover) chooses secret key: x in [1,p-1] and broadcast the public key: V := xG.
	Through the following protocol, Bob(i.e. Verifier) can be convinced that Alice knows x, but Bob does not
	learn x in this protocol.

	Step 1:
	- The prover randomly chooses an integer k in [1, p-1] and sends H := k*G and V to the verifier.
	Step 2:
	- The verifier randomly chooses two integers r, e in [0,p-1] and sends C:= r*G + e*H.
	Step 3:
	- The prover randomly chooses an integer a in [1, p-1] sends B := a*G to verifier.
	Step 4:
	- The verifier sends (e,r) to the prover.
	Step 5:
	- The prover verifies e in [0,p-1], r in [0,p-1], and C = r*G + e*H.
	- The prover computes z = a + ex mod p and sends k, z to prover.
	Step 6:
	- The verifier verifies z in [0,p-1], k in [1, p-1], H = k*G, and z*G = B + e*V

	ref: http://www.pinkas.net/sc/2014/lectures/lecture3.pdf
*/

// ECPoint is the struct for an elliptic curve point.
type InteractiveSchnorrProver struct {
	h *pt.ECPoint
	c *pt.ECPoint
	v *pt.ECPoint
	k *big.Int
	a *big.Int
	z *big.Int
	x *big.Int
}

type InteractiveSchnorrVerifier struct {
	h *pt.ECPoint
	e *big.Int
	r *big.Int
	c *pt.ECPoint
	v *pt.ECPoint
	b *pt.ECPoint
}

func NewInteractiveSchnorrProver(secret *big.Int, curve elliptic.Curve) (*InteractiveSchnorrProver, error) {
	k, err := utils.RandomPositiveInt(curve.Params().N)
	if err != nil {
		return nil, err
	}
	h := pt.ScalarBaseMult(curve, k)
	v := pt.ScalarBaseMult(curve, secret)
	return &InteractiveSchnorrProver{
		h: h,
		k: k,
		v: v,
		x: new(big.Int).Set(secret),
	}, nil
}

func (p *InteractiveSchnorrProver) ComputeZ(msg *InteractiveSchnorrVerifier2) (*InteractiveSchnorrProver3, error) {
	e := new(big.Int).SetBytes(msg.E)
	r := new(big.Int).SetBytes(msg.R)
	// check e in [0,p-1] and r in [0,p-1]
	curve := p.h.GetCurve()
	if utils.InRange(e, big0, curve.Params().N) != nil {
		return nil, ErrVerifyFailure
	}
	if utils.InRange(r, big0, curve.Params().N) != nil {
		return nil, ErrVerifyFailure
	}
	// check C = eH+rG
	eH := p.h.ScalarMult(e)
	rG := pt.NewBase(curve).ScalarMult(r)
	compareResult, err := eH.Add(rG)
	if err != nil {
		return nil, err
	}
	if !p.c.Equal(compareResult) {
		return nil, ErrVerifyFailure
	}
	// compute z = a + ex mod p
	z := new(big.Int).Mul(e, p.x)
	z = z.Add(z, p.a)
	z = z.Mod(z, curve.Params().N)
	return &InteractiveSchnorrProver3{
		Z: z.Bytes(),
		K: p.k.Bytes(),
	}, nil
}

func (p *InteractiveSchnorrProver) GetInteractiveSchnorrProver1Message() *InteractiveSchnorrProver1 {
	h, _ := p.h.ToEcPointMessage()
	pubKey, _ := p.v.ToEcPointMessage()
	return &InteractiveSchnorrProver1{
		H: h,
		V: pubKey,
	}
}

func (v *InteractiveSchnorrProver) GetV() *pt.ECPoint {
	return v.v
}

// B = a*G
func (p *InteractiveSchnorrProver) GetInteractiveSchnorrProver2Message() (*InteractiveSchnorrProver2, error) {
	curve := p.h.GetCurve()
	a, err := utils.RandomPositiveInt(curve.Params().N)
	if err != nil {
		return nil, err
	}
	p.a = a
	B := pt.ScalarBaseMult(curve, a)
	bMsg, _ := B.ToEcPointMessage()
	return &InteractiveSchnorrProver2{
		B: bMsg,
	}, nil
}

func (p *InteractiveSchnorrProver) SetCommitC(msg *InteractiveSchnorrVerifier1) error {
	c, err := msg.C.ToPoint()
	if err != nil {
		return err
	}
	p.c = c
	return nil
}

func NewInteractiveSchnorrVerifier(msg *InteractiveSchnorrProver1) (*InteractiveSchnorrVerifier, error) {
	h, err := msg.H.ToPoint()
	if err != nil {
		return nil, err
	}
	v, err := msg.V.ToPoint()
	if err != nil {
		return nil, err
	}
	curve := h.GetCurve()
	e, err := utils.RandomInt(curve.Params().N)
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomInt(curve.Params().N)
	if err != nil {
		return nil, err
	}
	c, err := computeCommitmentC(h, r, e)
	if err != nil {
		return nil, err
	}
	return &InteractiveSchnorrVerifier{
		h: h,
		e: e,
		r: r,
		c: c,
		v: v,
	}, nil
}

func computeCommitmentC(H *pt.ECPoint, r *big.Int, e *big.Int) (*pt.ECPoint, error) {
	// C = rG+eH
	G := pt.NewBase(H.GetCurve())
	var err error
	C := G.ScalarMult(r)
	eH := H.ScalarMult(e)
	C, err = C.Add(eH)
	if err != nil {
		return nil, err
	}
	return C, nil
}

func (v *InteractiveSchnorrVerifier) GetInteractiveSchnorrVerifier1Message() *InteractiveSchnorrVerifier1 {
	c, _ := v.c.ToEcPointMessage()
	return &InteractiveSchnorrVerifier1{
		C: c,
	}
}

func (v *InteractiveSchnorrVerifier) GetInteractiveSchnorrVerifier2Message() *InteractiveSchnorrVerifier2 {
	return &InteractiveSchnorrVerifier2{
		E: v.e.Bytes(),
		R: v.r.Bytes(),
	}
}

func (v *InteractiveSchnorrVerifier) SetB(msg *InteractiveSchnorrProver2) error {
	b, err := msg.B.ToPoint()
	if err != nil {
		return err
	}
	v.b = b
	return nil
}

// z*G = B + e*V
func (v *InteractiveSchnorrVerifier) Verify(msg *InteractiveSchnorrProver3) error {
	z := new(big.Int).SetBytes(msg.Z)
	k := new(big.Int).SetBytes(msg.K)
	curve := v.h.GetCurve()
	if utils.InRange(z, big0, curve.Params().N) != nil {
		return ErrVerifyFailure
	}
	if utils.InRange(k, big1, curve.Params().N) != nil {
		return ErrVerifyFailure
	}
	// Check h = k*G
	kG := pt.ScalarBaseMult(curve, k)
	if !v.h.Equal(kG) {
		return ErrVerifyFailure
	}

	zG := pt.NewBase(curve).ScalarMult(z)
	compareResult := v.v.ScalarMult(v.e)
	compareResult, err := compareResult.Add(v.b)
	if err != nil {
		return err
	}
	if !zG.Equal(compareResult) {
		return ErrVerifyFailure
	}
	return nil
}

func (v *InteractiveSchnorrVerifier) GetV() *pt.ECPoint {
	return v.v
}
