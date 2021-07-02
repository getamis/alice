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
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
)

/*
	Notations:
	- p : the cardinality of elliptic curve group。
	- G : a point of elliptic curve group
	- g : random power of the minimal lifting prime.
	- h : is g^a : a public key
	- s : ⌈1/π log|∆K|*|∆K|1/2⌉, π is pi
	- A : s*2^40
	- t : randomly choose [0, A-1]
	- C : 2^40
	- C’: [0, 2^40-1]
	- d : 40
	Alice(i.e. Prover) chooses the message x and a nonce r to get the CL ciphertext (c1 = g^r, c2=h^r*f^x) and the point Q = x*R.
	Through the following protocol, Bob(i.e. Verifier) can be convinced that Alice knows x and encrypted message and the point
	are consistency. But Bob does not learn x, r in this protocol. We use Fiat–Shamir heuristic to get the following protocol.
	Step 1: The prover
	- randomly chooses two integers r1 in [0, 2^{d}*A*C-1] and r2 in [0, p-1].
	- computes t1=g^{r1}, t2=h^{r1}f^{r2} and T =r2*R.
	- computes k:=H(t1, t2, g, f, h, p, T, Q, R, A, C) mod C. Here H is a cryptography hash function.
	- computes u1:=r1+kr in Z and u2:=r2+kx mod p. Here Z is the ring of integer. The resulting proof is (u1, u2, t1, t2, c1, c2, T, Q).
	Step 2: The verifier verifies
	- u1 in [0, (2^{d}+1)AC).
	- u2 in [0, p-1].
	- g^{u1}=t1*c1^k.
	- h^{u1}*f^{u2}=t2*(c2)^k
	- T+k*Q=u2*R
*/

func (publicKey *PublicKey) BuildConsistencyProof(data []byte, R *pt.ECPoint) (*ConsistencyProofMessage, error) {
	message := new(big.Int).SetBytes(data)
	c1, c2, r, err := publicKey.encrypt(message)
	if err != nil {
		return nil, err
	}
	Q := R.ScalarMult(message)
	proof, err := publicKey.buildProofWithPointQ(message, r, Q, R)
	if err != nil {
		return nil, err
	}
	msgR, err := R.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	return &ConsistencyProofMessage{
		C1:    c1,
		C2:    c2,
		Proof: proof,
		R:     msgR,
	}, nil
}

func (pubKey *PublicKey) buildProofWithPointQ(plainText *big.Int, r *big.Int, Q, R *pt.ECPoint) (*VerifyHashConsistencyProof, error) {
	// Compute 2^{d}ac + 1
	upperBound1 := new(big.Int).Mul(pubKey.a, pubKey.c)
	upperBound1 = upperBound1.Lsh(upperBound1, uint(pubKey.d))
	upperBound1 = upperBound1.Add(upperBound1, big1)

	// r1 in [0, 2^{d}AC]
	r1, err := utils.RandomInt(upperBound1)
	if err != nil {
		return nil, err
	}
	// r2 in [0, p-1]
	r2, err := utils.RandomInt(pubKey.p)
	if err != nil {
		return nil, err
	}
	// Compute t1=g^{r1} and t2=h^{r1}*f^{r2}
	t1, err := pubKey.g.Exp(r1)
	if err != nil {
		return nil, err
	}
	t2, err := pubKey.h.Exp(r1)
	if err != nil {
		return nil, err
	}
	fPower, err := pubKey.f.Exp(r2)
	if err != nil {
		return nil, err
	}
	t2, err = t2.Composition(fPower)
	if err != nil {
		return nil, err
	}

	T := R.ScalarMult(r2)
	msgT, err := T.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgR, err := R.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgQ, err := Q.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	// k:=H(t1, t2, g, f, h, p, T, Q, G, A, C) mod C
	// In our application C = 2^40.
	// The distribution E := { x| k mod C } is also the uniform distribution in [0,2^40-1]=[0,c-1].
	k, salt, err := utils.HashProtosRejectSampling(big256bit, &HashConsistencyProof{
		T1: t1.ToMessage(),
		T2: t2.ToMessage(),
		G:  pubKey.g.ToMessage(),
		F:  pubKey.f.ToMessage(),
		H:  pubKey.h.ToMessage(),
		P:  pubKey.p.Bytes(),
		Q:  msgQ,
		R:  msgR,
		T:  msgT,
		A:  pubKey.a.Bytes(),
		C:  pubKey.c.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	k = k.Mod(k, pubKey.c)

	// Compute u1:=r1+kr in Z and u2:=r2+k*plainText mod p
	u1 := new(big.Int).Mul(k, r)
	u1 = u1.Add(r1, u1)
	u2 := new(big.Int).Mul(k, plainText)
	u2 = u2.Add(u2, r2)
	u2 = u2.Mod(u2, pubKey.p)
	proof := &VerifyHashConsistencyProof{
		Salt: salt,
		U1:   u1.Bytes(),
		U2:   u2.Bytes(),
		T1:   t1.ToMessage(),
		T2:   t2.ToMessage(),
		Q:    msgQ,
		T:    msgT,
	}
	return proof, nil
}

func (pubKey *PublicKey) VerifyConsistencyProof(msgProof *ConsistencyProofMessage) error {
	msg := msgProof.Proof
	t1, err := msg.T1.ToBQuadraticForm()
	if err != nil {
		return ErrInvalidMessage
	}
	t2, err := msg.T2.ToBQuadraticForm()
	if err != nil {
		return ErrInvalidMessage
	}
	T, err := msg.T.ToPoint()
	if err != nil {
		return ErrInvalidMessage
	}
	Q, err := msg.Q.ToPoint()
	if err != nil {
		return ErrInvalidMessage
	}

	// Compute (2^{d}+1)ac + 1
	ac := new(big.Int).Mul(pubKey.c, pubKey.a)
	upperBound := new(big.Int).Lsh(ac, uint(pubKey.d))
	upperBound = upperBound.Add(upperBound, ac)
	upperBound = upperBound.Add(upperBound, big1)

	// u1 in [0, (2^{d}+1)Ac]
	u1 := new(big.Int).SetBytes(msg.U1)
	err = utils.InRange(u1, big0, upperBound)
	if err != nil {
		return err
	}

	// u2 in [0, p-1].
	u2 := new(big.Int).SetBytes(msg.U2)
	err = utils.InRange(u2, big0, pubKey.p)
	if err != nil {
		return err
	}
	R, err := msgProof.R.ToPoint()
	if err != nil {
		return err
	}

	// Check g^{u1}=t1*c1^k
	// k:=H(t1, t2, g, f, h, p, T, Q, R, A, C) mod C
	k, err := utils.HashProtosToInt(msg.Salt, &HashConsistencyProof{
		T1: t1.ToMessage(),
		T2: t2.ToMessage(),
		G:  pubKey.g.ToMessage(),
		F:  pubKey.f.ToMessage(),
		H:  pubKey.h.ToMessage(),
		P:  pubKey.p.Bytes(),
		Q:  msg.Q,
		R:  msgProof.R,
		T:  msg.T,
		A:  pubKey.a.Bytes(),
		C:  pubKey.c.Bytes(),
	})
	if err != nil {
		return err
	}
	k = k.Mod(k, pubKey.c)
	c1, err := msgProof.C1.ToBQuadraticForm()
	if err != nil {
		return err
	}
	c2, err := msgProof.C2.ToBQuadraticForm()
	if err != nil {
		return err
	}

	t1c1k, err := c1.Exp(k)
	if err != nil {
		return err
	}
	t1c1k, err = t1c1k.Composition(t1)
	if err != nil {
		return err
	}
	g := pubKey.g
	gu1, err := g.Exp(u1)
	if err != nil {
		return err
	}
	if !gu1.Equal(t1c1k) {
		return ErrDifferentBQForms
	}

	// Check h^{u1}*f^{u2}=t2*(c2)^k
	f := pubKey.f
	hu1fu2, err := f.Exp(u2)
	if err != nil {
		return err
	}
	h := pubKey.h
	hu1, err := h.Exp(u1)
	if err != nil {
		return err
	}
	hu1fu2, err = hu1fu2.Composition(hu1)
	if err != nil {
		return err
	}
	c2k, err := c2.Exp(k)
	if err != nil {
		return err
	}
	t2c2k, err := c2k.Composition(t2)
	if err != nil {
		return err
	}
	if !t2c2k.Equal(hu1fu2) {
		return ErrDifferentBQForms
	}

	// T+kQ=u2*R
	taddkQ := Q.ScalarMult(k)
	taddkQ, err = taddkQ.Add(T)
	if err != nil {
		return err
	}
	u2R := R.ScalarMult(u2)
	if !u2R.Equal(taddkQ) {
		return ErrFailedVerify
	}
	return nil
}
