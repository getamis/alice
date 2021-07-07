// Copyright © 2021 AMIS Technologies
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

package cl

import (
	"errors"
	"math/big"

	bqForm "github.com/getamis/alice/crypto/binaryquadraticform"
)

var (
	//ErrTrivialKey is returned if the public key is trivial
	ErrTrivialKey = errors.New("the public key is trivial")
)

type CLBaseParameter struct {
	p *big.Int // message space
	q *big.Int
	a *big.Int
	g bqForm.Exper
	f bqForm.Exper
	d uint32
	c *big.Int

	// cache value
	discriminantOrderP *big.Int
}

func NewCLBaseParameter(c *big.Int, d uint32, p *big.Int, safeParameter int, distributionDistance uint) (*CLBaseParameter, error) {
	// 0. Check that p is a prime with length(p) > 80  and safeParameter >= 1348 (The permitted security level ).
	if p.BitLen() < minimalBitLengthMessageSpace || !p.ProbablyPrime(1) {
		return nil, ErrNotBigPrime
	}

	if safeParameter < minimalSecurityLevel {
		return nil, ErrSmallSafeParameter
	}

	// 1. Ensure λ ≥ μ + 2
	lambda := safeParameter / 2
	mu := p.BitLen()
	if lambda < mu+2 {
		return nil, ErrSmallSafeParameter
	}

	// 2-3. Generate ΔK = -pq and ΔP = p^2 * ΔK
	q, err := generateAnotherPrimeQ(p, 2*lambda-mu)
	if err != nil {
		return nil, err
	}

	// Generate ΔK = -pq
	discriminantK := new(big.Int).Mul(p, q)
	discriminantK = discriminantK.Neg(discriminantK)

	// ΔP = p^2 * ΔK
	p2 := new(big.Int).Mul(p, p)
	discirminantP := new(big.Int).Mul(p2, discriminantK)

	// 4. f = (p^2, p)
	fa := new(big.Int).Set(p2)
	fb := new(big.Int).Set(p)
	f, err := bqForm.NewBQuadraticFormByDiscriminant(fa, fb, discirminantP)
	if err != nil {
		return nil, err
	}

	// generate r, generate a split prime in the maximal order Q(ΔK^(1/2))
	r, err := generateR(discriminantK)
	if err != nil {
		return nil, err
	}
	// Get the lying above prime hat{r}
	rForm, err := generateLyingAbovePrime(discriminantK, r)
	if err != nil {
		return nil, err
	}

	// 6. Compute o by the lifting formula
	o, err := generateGeneratorInG(rForm, f, p)
	if err != nil {
		return nil, err
	}

	// 7. Compute Ceil(1/π(ln|ΔK|))*([|ΔK|^(1/2)]+1) (i.e. New paper: Bandwidth-efficient threshold EC-DSA parameter, old version is set it to be |ΔK|^(3/4)).
	s := getUpperBoundClassGroupMaximalOrder(discriminantK)

	// Build a private key
	// a = 2^(distributionDistance)*s
	a := new(big.Int).Lsh(s, distributionDistance)

	// Compute g = o^b for some b in [1,a).
	g, err := getNonIdentityGenerator(o, a)
	if err != nil {
		return nil, err
	}

	return &CLBaseParameter{
		p:                  p,
		q:                  q,
		a:                  a,
		g:                  g,
		d:                  d,
		c:                  c,
		f:                  f,
		discriminantOrderP: discirminantP,
	}, nil
}

func (basePara *CLBaseParameter) GeneratePublicKey(h *bqForm.BQuadraticForm) (*PublicKey, error) {
	identityKey, err := basePara.g.Exp(big0)
	if err != nil {
		return nil, err
	}
	if h.Equal(identityKey) {
		return nil, ErrTrivialKey
	}
	return &PublicKey{
		p:                  basePara.p,
		q:                  basePara.q,
		a:                  basePara.a,
		g:                  basePara.g,
		f:                  basePara.f,
		d:                  basePara.d,
		h:                  h,
		c:                  basePara.c,
		proof:              nil,
		discriminantOrderP: basePara.discriminantOrderP,
	}, nil
}

func (basePara *CLBaseParameter) GetG() bqForm.Exper {
	return basePara.g
}

func (basePara *CLBaseParameter) ToMessage() *ClBaseParameterMessage {
	return &ClBaseParameterMessage{
		Q: basePara.q.Bytes(),
		G: basePara.g.ToMessage(),
	}
}

func (basePara *ClBaseParameterMessage) ToBase(c *big.Int, d uint32, p *big.Int, safeParameter int, distributionDistance uint) (*CLBaseParameter, error) {
	// Validate message
	q := new(big.Int).SetBytes(basePara.Q)
	if !q.ProbablyPrime(10) {
		return nil, ErrNotBigPrime
	}
	g, err := basePara.G.ToBQuadraticForm()
	if err != nil {
		return nil, err
	}

	discriminantK := new(big.Int).Mul(p, q)
	discriminantK = discriminantK.Neg(discriminantK)
	if discriminantK.BitLen() < safeParameter {
		return nil, ErrFailedVerify
	}

	p2 := new(big.Int).Mul(p, p)
	discirminantP := new(big.Int).Mul(p2, discriminantK)

	fa := new(big.Int).Set(p2)
	fb := new(big.Int).Set(p)
	f, err := bqForm.NewBQuadraticFormByDiscriminant(fa, fb, discirminantP)
	if err != nil {
		return nil, err
	}
	s := getUpperBoundClassGroupMaximalOrder(discriminantK)
	// Build a private key
	// a = 2^(distributionDistance)*s
	a := new(big.Int).Lsh(s, distributionDistance)
	return &CLBaseParameter{
		p:                  p,
		q:                  q,
		a:                  a,
		g:                  g,
		d:                  d,
		c:                  c,
		f:                  f,
		discriminantOrderP: discirminantP,
	}, nil
}
