// Copyright © 2019 AMIS Technologies
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
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	// maxGenN defines the max retries to generate N
	maxGenN = 100
	// maxGenG defines the max retries to generate G
	maxGenG = 100
)

var (
	// ErrInvalidMessage is returned if the message is invalid
	ErrInvalidMessage = errors.New("invalid message")
)

// PublicKey is (n, g)
type PublicKey struct {
	// N is the plaintext space
	n *big.Int
	// NSquare is the encrypted text space
	nSquare *big.Int
	g       *big.Int
}

func (pub *PublicKey) GetN() *big.Int {
	return new(big.Int).Set(pub.n)
}

func (pub *PublicKey) GetNSquare() *big.Int {
	return new(big.Int).Set(pub.nSquare)
}

func (pub *PublicKey) GetG() *big.Int {
	return new(big.Int).Set(pub.g)
}

func (pub *PublicKey) Copy() *PublicKey {
	return &PublicKey{
		n:       pub.GetN(),
		nSquare: pub.GetNSquare(),
		g:       pub.GetG(),
	}
}

func (pub *PublicKey) Encrypt(m *big.Int) (*big.Int, error) {
	// Ensure 0 <= m < n
	if m.Sign() < 0 {
		return nil, ErrInvalidMessage
	}
	if m.Cmp(pub.n) >= 0 {
		return nil, ErrInvalidMessage
	}

	// gcd(r, n)=1
	r, err := RandomCoprimeInt(pub.n)
	if err != nil {
		return nil, err
	}

	// c = (g^m * r^n) mod n^2
	gm := new(big.Int).Exp(pub.g, m, pub.nSquare) // g^m
	rn := new(big.Int).Exp(r, pub.n, pub.nSquare) // r^n
	c := new(big.Int).Mul(gm, rn)
	c = c.Mod(c, pub.nSquare)
	return c, nil
}

// https://en.wikipedia.org/wiki/Paillier_cryptosystem
// Add implements homomorphic addition of plaintexts
func (pub *PublicKey) Add(encA *big.Int, encB *big.Int) *big.Int {
	encAB := new(big.Int).Mul(encA, encB)
	ret := new(big.Int).Mod(encAB, pub.nSquare)
	return ret
}

// https://en.wikipedia.org/wiki/Paillier_cryptosystem
// Mul implements homomorphic multiplication of plaintexts
func (pub *PublicKey) Mul(encA *big.Int, scalar *big.Int) *big.Int {
	return new(big.Int).Exp(encA, scalar, pub.nSquare)
}

// https://en.wikipedia.org/wiki/Paillier_cryptosystem
// Paillier implements the Paillier crypto system
type Paillier struct {
	// public key
	*PublicKey

	// private key
	lambda *big.Int // λ=lcm(p−1, q−1)
	mu     *big.Int // μ=(L(g^λ mod n^2))^-1 mod n
}

func NewPaillier(keySize int) (*Paillier, error) {
	n, lambda, err := getNAndLambda(keySize)
	if err != nil {
		return nil, err
	}
	nSquare := new(big.Int).Mul(n, n) // n^2
	g, mu, err := getGAndMu(lambda, n, nSquare)
	if err != nil {
		return nil, err
	}
	return &Paillier{
		lambda: lambda,
		mu:     mu,
		PublicKey: &PublicKey{
			n:       n,
			nSquare: nSquare,
			g:       g,
		},
	}, nil
}

// Decrypt computes the plaintext from the ciphertext
func (p *Paillier) Decrypt(c *big.Int) (*big.Int, error) {
	// Ensure 0 < c < n^2
	if c.Sign() <= 0 {
		return nil, ErrInvalidMessage
	}
	if c.Cmp(p.PublicKey.nSquare) >= 0 {
		return nil, ErrInvalidMessage
	}

	// c and n should be relative prime
	if !IsRelativePrime(c, p.PublicKey.n) {
		return nil, ErrInvalidMessage
	}

	x := new(big.Int).Exp(c, p.lambda, p.PublicKey.nSquare)
	l, err := lFunction(x, p.PublicKey.n)
	if err != nil {
		return nil, err
	}
	l = l.Mul(l, p.mu)
	l = l.Mod(l, p.PublicKey.n)
	return l, nil
}

func (p *Paillier) Copy() *Paillier {
	return &Paillier{
		lambda:    new(big.Int).Set(p.lambda),
		mu:        new(big.Int).Set(p.mu),
		PublicKey: p.PublicKey.Copy(),
	}
}

// getNAndLambda returns N and lambda.
// n = pq and lambda = lcm(p-1, q-1)
func getNAndLambda(keySize int) (*big.Int, *big.Int, error) {
	pqSize := keySize / 2
	for i := 0; i < maxGenN; i++ {
		// random two primes p and q
		p, err := rand.Prime(rand.Reader, pqSize)
		if err != nil {
			return nil, nil, err
		}
		q, err := rand.Prime(rand.Reader, pqSize)
		if err != nil {
			return nil, nil, err
		}
		// retry if p == q
		if p.Cmp(q) == 0 {
			continue
		}
		pMinus1 := new(big.Int).Sub(p, Big1)    // p-1
		qMinus1 := new(big.Int).Sub(q, Big1)    // q-1
		n := new(big.Int).Mul(p, q)             // n=p*q
		m := new(big.Int).Mul(pMinus1, qMinus1) // m=(p-1)*(q-1)
		// gcd(pq, (p-1)(q-1)) = 1
		if IsRelativePrime(n, m) {
			lambda, err := Lcm(pMinus1, qMinus1)
			if err == nil {
				return n, lambda, err
			}
		}
	}
	return nil, nil, ErrExceedMaxRetry
}

// getGAndMu returns G and mu.
func getGAndMu(lambda *big.Int, n *big.Int, nSquare *big.Int) (*big.Int, *big.Int, error) {
	for i := 0; i < maxGenG; i++ {
		g, err := RandomCoprimeInt(nSquare) // g
		if err != nil {
			return nil, nil, err
		}
		x := new(big.Int).Exp(g, lambda, nSquare) // x
		u, err := lFunction(x, n)
		if err != nil {
			return nil, nil, err
		}

		mu := new(big.Int).ModInverse(u, n)
		// if mu is nil, it means u and n are not relatively prime. We need to try again
		if mu == nil {
			continue
		}
		return g, mu, nil
	}
	return nil, nil, ErrExceedMaxRetry
}

// lFunction computes L(x)=(x-1)/n
func lFunction(x, n *big.Int) (*big.Int, error) {
	if n.Cmp(Big0) <= 0 {
		return nil, ErrInvalidInput
	}
	if x.Cmp(Big0) <= 0 {
		return nil, ErrInvalidInput
	}
	t := new(big.Int).Sub(x, Big1)
	m := new(big.Int)
	t, m = t.DivMod(t, n, m)
	if m.Cmp(Big0) != 0 {
		return nil, ErrInvalidInput
	}
	return t, nil
}
