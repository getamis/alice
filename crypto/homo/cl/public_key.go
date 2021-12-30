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

package cl

import (
	"math/big"

	binaryquadraticform "github.com/aisuosuo/alice/crypto/binaryquadraticform"
	bqForm "github.com/aisuosuo/alice/crypto/binaryquadraticform"
	"github.com/aisuosuo/alice/crypto/utils"
)

const (
	// d = 90 Fig. 6 in paper. But a = 2^(40)*s. If we want to get 90, then we set it to be 90-40=50
	distributionConstant = 50
)

var (
	// the size of challenge space = 1024
	sizeChallengeSpace = big.NewInt(1024)
)

/*
	Notations:
	- private key: x
	- a fixed generator: g
	- public key: h = g^x
	- s : an upper bound of 1/π(ln|ΔK|)|ΔK|^(1/2) i.e. In this implementation, we set it to be Ceil(1/π(ln|ΔK|))*([|ΔK|^(1/2)]+1).
	- challenge set c
	- the message space: [0, p-1]. In our situation, the value p is the order of an elliptic curve group.
	- distributionConstant: d

	Alice(i.e. Prover) chooses a secret key: x in [1,s*2^d] and broadcasts the public key: h = g^x
	Through the following protocol, Bob(i.e. Verifier) can be convinced that Alice knows x such that h^y = g^z for some z, and y = lcm(1,2,3,...,2^10), but Bob does not
	learn x in this protocol. We use Fiat–Shamir heuristic in the original protocol to get the following:

	Step 1: The prover
	- randomly chooses an integers r in [1, 2^{d}*s].
	- computes t=g^{r}.
	- computes k:=H(t, g, f, h, p, q, A, C) mod c. Here H is a cryptography hash function.
	- computes u:=r+kx in Z. Here Z is the ring of integer. The resulting proof is (u, t, h).
	Step 2: The verifier verifies
	- u in [0, (2^{d}+2^(50))s]. (Note: x in [0,s*2^(40)]. Then c*x in [0,s*2^50]. (2^{d}+2^(50))s = (2^(50)+2^(10))a).
	- g^{u}=t*h^k.
	Note: In our setting, d = 90.
*/

func newPubKey(proof *ProofMessage, d uint32, discirminantP *big.Int, a, c, p, q *big.Int, g, f, h *binaryquadraticform.BQuadraticForm) (*PublicKey, error) {
	publicKey := &PublicKey{
		p:                  p,
		q:                  q,
		a:                  a,
		g:                  bqForm.NewCacheExp(g),
		f:                  bqForm.NewCacheExp(f),
		h:                  bqForm.NewCacheExp(h),
		c:                  c,
		d:                  d,
		discriminantOrderP: discirminantP,
		proof:              proof,
	}
	err := publicKey.Verify()
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func newPubKeyProof(x *big.Int, a, c, p, q *big.Int, g, f, h *binaryquadraticform.BQuadraticForm) (*ProofMessage, error) {
	// Compute 2^{90}s = 2^(50)*a. Note that a = 2^(40)*s
	upperBound1 := new(big.Int).Lsh(a, distributionConstant)

	// r in [1, 2^{90}s] = [1, 2^50*a]
	r, err := utils.RandomPositiveInt(upperBound1)
	if err != nil {
		return nil, err
	}
	// Compute t=g^{r}
	t, err := g.Exp(r)
	if err != nil {
		return nil, err
	}

	// k:=H(t, g, f, h, p, q, A, C) mod c
	// In our application c = 1024. If the field order is 2^32, we will get the uniform distribution D in [0,2^32-1].
	// If we consider the distribution E := { x in D| x mod c } is also the uniform distribution in [0,1023]=[0,c-1].
	k, salt, err := utils.HashProtosRejectSampling(big256bit, &Hash{
		T1: t.ToMessage(),
		T2: nil,
		G:  g.ToMessage(),
		F:  f.ToMessage(),
		H:  h.ToMessage(),
		P:  p.Bytes(),
		Q:  q.Bytes(),
		A:  a.Bytes(),
		C:  c.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	k = k.Mod(k, sizeChallengeSpace)

	// Compute u:=r+kx in Z
	u := new(big.Int).Mul(k, x)
	u = u.Add(r, u)
	proof := &ProofMessage{
		Salt: salt,
		U1:   u.Bytes(),
		U2:   nil,
		T1:   t.ToMessage(),
		T2:   nil,
	}
	return proof, nil
}

func (pubKey *PublicKey) Verify() error {
	proof := pubKey.GetPubKeyProof()
	t, err := proof.T1.ToBQuadraticForm()
	if err != nil {
		return ErrInvalidMessage
	}

	// Compute (2^(50)+2^(10))a)
	upperBound := new(big.Int).Add(new(big.Int).Lsh(pubKey.a, 50), new(big.Int).Lsh(pubKey.a, 10))

	// u in [0, (2^{d}+2^(50))s] = [0, (2^(50)+2^(10))a)]
	u := new(big.Int).SetBytes(proof.U1)
	err = utils.InRange(u, big0, upperBound)
	if err != nil {
		return err
	}

	// Check g^{u1}=t1*c1^k
	// k:=H(t1, t2, g, f, h, p, q, a, c) mod c
	k, err := utils.HashProtosToInt(proof.Salt, &Hash{
		T1: proof.T1,
		T2: proof.T2,
		G:  pubKey.g.ToMessage(),
		F:  pubKey.f.ToMessage(),
		H:  pubKey.h.ToMessage(),
		P:  pubKey.p.Bytes(),
		Q:  pubKey.q.Bytes(),
		A:  pubKey.a.Bytes(),
		C:  pubKey.c.Bytes(),
	})
	if err != nil {
		return err
	}
	k = k.Mod(k, sizeChallengeSpace)

	// g^{u}=t*h^k
	thk, err := pubKey.h.Exp(k)
	if err != nil {
		return err
	}
	thk, err = thk.Composition(t)
	if err != nil {
		return err
	}
	g := pubKey.g
	gu, err := g.Exp(u)
	if err != nil {
		return err
	}
	if !gu.Equal(thk) {
		return ErrDifferentBQForms
	}
	return nil
}
