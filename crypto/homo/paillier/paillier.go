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

package paillier

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/golang/protobuf/proto"
)

const (
	// safePubKeySize is the permitted lowest size of Public Key.
	safePubKeySize = 2048

	// maxGenN defines the max retries to generate N
	maxGenN = 100
	// maxGenG defines the max retries to generate G
	maxGenG = 100
)

var (
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
	//ErrInvalidInput is returned if the input is invalid
	ErrInvalidInput = errors.New("invalid input")
	//ErrInvalidMessage is returned if the message is invalid
	ErrInvalidMessage = errors.New("invalid message")
	//ErrSmallPublicKeySize is returned if the size of public key is small
	ErrSmallPublicKeySize = errors.New("small public key")

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
)

// publicKey is (n, g)
type publicKey struct {
	n   *big.Int
	g   *big.Int
	msg *PubKeyMessage

	// cache value
	nSquare *big.Int
}

func (pub *publicKey) GetMessageRange(fieldOrder *big.Int) *big.Int {
	rangeK := computeStatisticalClosedRange(fieldOrder)
	return new(big.Int).Sub(pub.n, rangeK)
}

func (pub *publicKey) GetNSquare() *big.Int {
	return new(big.Int).Set(pub.nSquare)
}

func (pub *publicKey) GetN() *big.Int {
	return new(big.Int).Set(pub.n)
}

func (pub *publicKey) GetG() *big.Int {
	return new(big.Int).Set(pub.g)
}

func (pub *publicKey) Encrypt(mBytes []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(mBytes)
	// Ensure 0 <= m < n
	if m.Cmp(pub.n) >= 0 {
		return nil, ErrInvalidMessage
	}

	// gcd(r, n)=1
	r, err := utils.RandomCoprimeInt(pub.n)
	if err != nil {
		return nil, err
	}

	// c = (g^m * r^n) mod n^2
	gm := new(big.Int).Exp(pub.g, m, pub.nSquare) // g^m
	rn := new(big.Int).Exp(r, pub.n, pub.nSquare) // r^n
	c := new(big.Int).Mul(gm, rn)
	c = c.Mod(c, pub.nSquare)
	return c.Bytes(), nil
}

// In paillier, we cannot verify enc message. Therefore, we always return nil.
func (pub *publicKey) VerifyEnc([]byte) error {
	return nil
}

func (p *Paillier) GetPubKey() homo.Pubkey {
	return p.publicKey
}

// Refer: https://en.wikipedia.org/wiki/Paillier_cryptosystem
// privateKey is (λ, μ)
type privateKey struct {
	lambda *big.Int // λ=lcm(p−1, q−1)
	mu     *big.Int // μ=(L(g^λ mod n^2))^-1 mod n
}

type Paillier struct {
	*publicKey
	privateKey *privateKey
}

func NewPaillier(keySize int) (*Paillier, error) {
	if keySize < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}
	return NewPaillierUnSafe(keySize)
}

// Warning: No check the size of public key. This function is only used in Test.
func NewPaillierUnSafe(keySize int) (*Paillier, error) {
	p, q, n, lambda, err := getNAndLambda(keySize)
	if err != nil {
		return nil, err
	}
	g, mu, err := getGAndMu(lambda, n)
	if err != nil {
		return nil, err
	}
	msg, err := zkproof.NewIntegerFactorizationProofMessage([]*big.Int{p, q}, n)
	if err != nil {
		return nil, err
	}
	pubKeyMessage := &PubKeyMessage{
		Proof: msg,
		G:     g.Bytes(),
	}
	pub, err := pubKeyMessage.ToPubkey()
	if err != nil {
		return nil, err
	}
	return &Paillier{
		publicKey: pub,
		privateKey: &privateKey{
			lambda: lambda,
			mu:     mu,
		},
	}, nil
}

// Decrypt computes the plaintext from the ciphertext
func (p *Paillier) Decrypt(cBytes []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cBytes)
	pub := p.publicKey
	priv := p.privateKey

	err := isCorrectCiphertext(c, pub)
	if err != nil {
		return nil, err
	}

	x := new(big.Int).Exp(c, priv.lambda, pub.nSquare)
	l, err := lFunction(x, pub.n)
	if err != nil {
		return nil, err
	}
	l = l.Mul(l, priv.mu)
	l = l.Mod(l, pub.n)
	return l.Bytes(), nil
}

func (p *Paillier) NewPubKeyFromBytes(bs []byte) (homo.Pubkey, error) {
	msg := &PubKeyMessage{}
	err := proto.Unmarshal(bs, msg)
	if err != nil {
		return nil, err
	}
	return msg.ToPubkey()
}

func (p *Paillier) GetMtaProof(curve elliptic.Curve, _ *big.Int, a *big.Int) ([]byte, error) {
	proofMsg, err := zkproof.NewBaseSchorrMessage(curve, a)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(proofMsg)
}

func (p *Paillier) VerifyMtaProof(bs []byte, curve elliptic.Curve, _ *big.Int, _ *big.Int) (*pt.ECPoint, error) {
	msg := &zkproof.SchnorrProofMessage{}
	err := proto.Unmarshal(bs, msg)
	if err != nil {
		return nil, err
	}

	err = msg.Verify(pt.NewBase(curve))
	if err != nil {
		return nil, err
	}

	return msg.V.ToPoint()
}

// getNAndLambda returns N and lambda.
// n = pq and lambda = lcm(p-1, q-1)
func getNAndLambda(keySize int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	pqSize := keySize / 2
	for i := 0; i < maxGenN; i++ {
		// random two primes p and q
		p, err := rand.Prime(rand.Reader, pqSize)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		q, err := rand.Prime(rand.Reader, pqSize)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// Because the bit length of p and q are the same and p!= q, GCD(p, q)=1.
		if p.Cmp(q) == 0 {
			continue
		}

		pMinus1 := new(big.Int).Sub(p, big1)    // p-1
		qMinus1 := new(big.Int).Sub(q, big1)    // q-1
		n := new(big.Int).Mul(p, q)             // n=p*q
		m := new(big.Int).Mul(pMinus1, qMinus1) // m=(p-1)*(q-1)
		// gcd(pq, (p-1)(q-1)) = 1
		if utils.IsRelativePrime(n, m) {
			lambda, err := utils.Lcm(pMinus1, qMinus1)
			if err == nil {
				return p, q, n, lambda, err
			}
		}
	}
	return nil, nil, nil, nil, ErrExceedMaxRetry
}

func isCorrectCiphertext(c *big.Int, pubKey *publicKey) error {
	// Ensure 0 < c < n^2
	err := utils.InRange(c, big1, pubKey.nSquare)
	if err != nil {
		return err
	}
	// c and n should be relative prime
	if !utils.IsRelativePrime(c, pubKey.n) {
		return ErrInvalidMessage
	}
	return nil
}

// getGAndMu returns G and mu.
func getGAndMu(lambda *big.Int, n *big.Int) (*big.Int, *big.Int, error) {
	nSquare := new(big.Int).Mul(n, n) // n^2
	for i := 0; i < maxGenG; i++ {
		g, err := utils.RandomCoprimeInt(nSquare) // g
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
	if n.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}
	if x.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}
	t := new(big.Int).Sub(x, big1)
	t = t.Div(t, n)
	return t, nil
}

/*
	1. Check that c1, c2 is correct.
	2. Choose (r, N)=1 with r in [1, N-1] randomly.
	3. Compute c1*c2*r^N mod N^2.
*/
func (pub *publicKey) Add(c1Bytes []byte, c2Bytes []byte) ([]byte, error) {
	c1 := new(big.Int).SetBytes(c1Bytes)
	c2 := new(big.Int).SetBytes(c2Bytes)
	err := isCorrectCiphertext(c1, pub)
	if err != nil {
		return nil, err
	}
	err = isCorrectCiphertext(c2, pub)
	if err != nil {
		return nil, err
	}

	result := new(big.Int).Mul(c1, c2)
	result = result.Mod(result, pub.nSquare)

	r, err := utils.RandomCoprimeInt(pub.n)
	if err != nil {
		return nil, err
	}
	rn := new(big.Int).Exp(r, pub.n, pub.nSquare)
	result = result.Mul(result, rn)
	result = result.Mod(result, pub.nSquare)
	return result.Bytes(), nil
}

/*
	1. Check that c is correct.
	2. Compute scalar mod N.
	3. Choose (r, N)=1 with r in [1, N-1] randomly.
	4. Compute c^scalar*r^N mod N^2.
*/
func (pub *publicKey) MulConst(cBytes []byte, scalar *big.Int) ([]byte, error) {
	c := new(big.Int).SetBytes(cBytes)
	err := isCorrectCiphertext(c, pub)
	if err != nil {
		return nil, err
	}
	scalarModN := new(big.Int).Mod(scalar, pub.n)
	result := new(big.Int).Exp(c, scalarModN, pub.nSquare)
	r, err := utils.RandomCoprimeInt(pub.n)
	if err != nil {
		return nil, err
	}
	rn := new(big.Int).Exp(r, pub.n, pub.nSquare)
	result = result.Mul(result, rn)
	result = result.Mod(result, pub.nSquare)
	return result.Bytes(), nil
}

func (pub *publicKey) ToPubKeyBytes() []byte {
	// We can ignore this error, because the resulting message is produced by ourself.
	bs, _ := proto.Marshal(pub.msg)
	return bs
}

func computeStatisticalClosedRange(n *big.Int) *big.Int {
	nMinus := new(big.Int).Sub(n, big1)
	nMinusSquare := new(big.Int).Exp(nMinus, big2, nil)
	return nMinusSquare
}
