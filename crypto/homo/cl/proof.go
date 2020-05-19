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
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/proto"
)

var (
	big0      = big.NewInt(0)
	big256bit = new(big.Int).Lsh(big1, 256)

	// ErrDifferentBQForms is returned if the two quadratic forms are different
	ErrDifferentBQForms = errors.New("different binary quadratic Forms")
)

/*
	Notations:
	- upperboundOrder: A
	- public key: h
	- ciphertext: (c1, c2)=(g^r, f^a*h^r)
	- challenge set c
	- the message space: [0, p-1]. In our situation, the value p is the order of an elliptic curve group.
	- distributionDistance: d

	Alice(i.e. Prover) chooses the message a and a nonce r to get the CL ciphertext (c1, c2).
	Through the following protocol, Bob(i.e. Verifier) can be convinced that Alice knows a, r, but Bob does not
	learn a, r in this protocol. We use Fiat–Shamir heuristic to get the following protocol.

	Step 1: The prover
	- randomly chooses two integers r1 in [0, 2^{d}Ac] and r2 in [0, p-1].
	- computes t1=g^{r1} and t2=h^{r1}f^{r2}.
	- computes k:=H(t1, t2, g, f, h, p, q) mod c. Here H is a cryptography hash function.
	- computes u1:=r1+kr in Z and u2:=r2+ka. Here Z is the ring of integer. The resulting proof is (u1,  u2, t1, t2, c1, c2).
	Step 2: The verifier verifies
	- u1 in [0, (2^{d}+1)Ac].
	- u2 in [0, p-1].
	- g^{u1}=t1*c1^k.
	- h^{u1}*f^{u2}=t2*(c2)^k
*/

func (pubKey *PublicKey) buildProof(plainText *big.Int, r *big.Int) (*ProofMessage, error) {
	// Compute 2^{d}ac + 1
	upperBound1 := new(big.Int).Mul(pubKey.a, pubKey.c)
	upperBound1 = upperBound1.Lsh(upperBound1, uint(pubKey.d))
	upperBound1 = upperBound1.Add(upperBound1, big1)

	// r1 in [0, 2^{d}Ac]
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

	// k:=H(t1, t2, g, f, h, p, q, a, c) mod c
	// In our application c = 1024. If the field order is 2^32, we will get the uniform distribution D in [0,2^32-1].
	// If we consider the distribution E := { x in D| x mod c } is also the uniform distribution in [0,1023]=[0,c-1].
	k, salt, err := utils.HashProtosRejectSampling(big256bit, &Hash{
		T1: t1.ToMessage(),
		T2: t2.ToMessage(),
		G:  pubKey.g.ToMessage(),
		F:  pubKey.f.ToMessage(),
		H:  pubKey.h.ToMessage(),
		P:  pubKey.p.Bytes(),
		Q:  pubKey.q.Bytes(),
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
	proof := &ProofMessage{
		Salt: salt,
		U1:   u1.Bytes(),
		U2:   u2.Bytes(),
		T1:   t1.ToMessage(),
		T2:   t2.ToMessage(),
	}
	return proof, nil
}

func (pubKey *PublicKey) VerifyEnc(bs []byte) error {
	msg := &EncryptedMessage{}
	err := proto.Unmarshal(bs, msg)
	if err != nil {
		return err
	}
	t1, err := msg.Proof.T1.ToBQuadraticForm()
	if err != nil {
		return ErrInvalidMessage
	}
	t2, err := msg.Proof.T2.ToBQuadraticForm()
	if err != nil {
		return ErrInvalidMessage
	}
	c1, c2, err := msg.getBQs(pubKey.discriminantOrderP)
	if err != nil {
		return ErrInvalidMessage
	}

	// Compute (2^{d}+1)ac + 1
	ac := new(big.Int).Mul(pubKey.c, pubKey.a)
	upperBound := new(big.Int).Lsh(ac, uint(pubKey.d))
	upperBound = upperBound.Add(upperBound, ac)
	upperBound = upperBound.Add(upperBound, big1)

	// u1 in [0, (2^{d}+1)Ac]
	u1 := new(big.Int).SetBytes(msg.Proof.U1)
	err = utils.InRange(u1, big0, upperBound)
	if err != nil {
		return err
	}

	// u2 in [0, p-1].
	u2 := new(big.Int).SetBytes(msg.Proof.U2)
	err = utils.InRange(u2, big0, pubKey.p)
	if err != nil {
		return err
	}
	// Check g^{u1}=t1*c1^k
	// k:=H(t1, t2, g, f, h, p, q, a, c) mod c
	k, err := utils.HashProtosToInt(msg.Proof.Salt, &Hash{
		T1: msg.Proof.T1,
		T2: msg.Proof.T2,
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
	k = k.Mod(k, pubKey.c)

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
	return nil
}
