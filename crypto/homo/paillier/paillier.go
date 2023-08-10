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
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/elliptic"

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
	// maxRetry defines the max retries
	maxRetry = 100

	// set the min number of zk proofs
	numberZkProof = 80
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
	//ErrSmallFactorPubKey is returned if there exist small factor of a public key
	ErrSmallFactorPubKey = errors.New("there exist small factor of a public key")

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
)

// publicKey is (n, g)
type publicKey struct {
	n *big.Int
	g *big.Int

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
	c, _, err := pub.EncryptWithOutputSalt(m)
	if err != nil {
		return nil, err
	}
	//c.Mod(c, pub.nSquare)
	return c.Bytes(), nil
}

func (pub *publicKey) EncryptWithOutputSalt(m *big.Int) (*big.Int, *big.Int, error) {
	// gcd(r, n)=1
	r, err := utils.RandomCoprimeInt(pub.n)
	if err != nil {
		return nil, nil, err
	}

	// c = (g^m * r^n) mod n^2
	gm := new(big.Int).Exp(pub.g, m, pub.nSquare) // g^m
	rn := new(big.Int).Exp(r, pub.n, pub.nSquare) // r^n
	c := new(big.Int).Mul(gm, rn)
	c = c.Mod(c, pub.nSquare)
	return c, r, nil
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
	p      *big.Int
	q      *big.Int
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
	return NewPaillierUnSafe(keySize, false)
}

func NewPaillierSafePrime(keySize int) (*Paillier, error) {
	if keySize < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}
	return NewPaillierUnSafe(keySize, true)
}

// Warning: Only use in test.
func NewPaillierWithGivenPrimes(p, q *big.Int) (*Paillier, error) {
	n := new(big.Int).Mul(p, q)
	g := new(big.Int).Add(n, big1)
	lambda, err := utils.EulerFunction([]*big.Int{p, q})
	if err != nil {
		return nil, err
	}
	mu := new(big.Int).ModInverse(lambda, n)
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
			p:      p,
			q:      q,
			lambda: lambda,
			mu:     mu,
		},
	}, nil
}

// Warning: No check the size of public key.
func NewPaillierUnSafe(keySize int, isSafe bool) (*Paillier, error) {
	p, q, n, lambda, err := getNAndLambda(keySize, isSafe)
	if err != nil {
		return nil, err
	}
	g, mu, err := getGAndMuWithSpecialG(lambda, n)
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
			p:      p,
			q:      q,
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
	// Check no small factor
	pubKey, err := msg.ToPubkey()
	if err != nil {
		return nil, err
	}
	for i:=0; i < len(primes); i++ {
		if new(big.Int).Mod(pubKey.n, big.NewInt(primes[i])).Cmp(big0) == 0 {
			return nil, ErrSmallFactorPubKey
		}
	}
	return pubKey, nil
}

func (p *Paillier) GetMtaProof(curve elliptic.Curve, beta *big.Int, b *big.Int) ([]byte, error) {
	proofMsgB, err := zkproof.NewBaseSchorrMessage(curve, b)
	if err != nil {
		return nil, err
	}
	betaModOrder := new(big.Int).Mod(beta, curve.Params().N)
	proofMsgBeta, err := zkproof.NewBaseSchorrMessage(curve, betaModOrder)
	if err != nil {
		return nil, err
	}
	zkBetaAndBProof := &ZkBetaAndBMessage{
		ProofB:    proofMsgB,
		ProofBeta: proofMsgBeta,
	}
	return proto.Marshal(zkBetaAndBProof)
}

func (p *Paillier) VerifyMtaProof(bs []byte, curve elliptic.Curve, alpha *big.Int, a *big.Int) (*pt.ECPoint, error) {
	msg := &ZkBetaAndBMessage{}
	err := proto.Unmarshal(bs, msg)
	if err != nil {
		return nil, err
	}
	err = msg.ProofB.Verify(pt.NewBase(curve))
	if err != nil {
		return nil, err
	}
	err = msg.ProofBeta.Verify(pt.NewBase(curve))
	if err != nil {
		return nil, err
	}
	B, err := msg.ProofB.V.ToPoint()
	if err != nil {
		return nil, err
	}
	Beta, err := msg.ProofBeta.V.ToPoint()
	if err != nil {
		return nil, err
	}
	G := pt.NewBase(B.GetCurve())
	alphaG := G.ScalarMult(alpha)
	compare := B.ScalarMult(a)
	compare, err = compare.Add(Beta)
	if err != nil {
		return nil, err
	}
	// Simplify MTA: check alphaG = a*B + Beta. New Theorem.
	if !alphaG.Equal(compare) {
		return nil, ErrInvalidMessage
	}
	return B, nil
}

// getNAndLambda returns N and lambda.
// n = pq and lambda = lcm(p-1, q-1)
func getNAndLambda(keySize int, isSafe bool) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	pqSize := keySize / 2
	for i := 0; i < maxGenN; i++ {
		p, q, err := generatePrime(isSafe, pqSize)
		if err != nil {
			return nil, nil, nil, nil, err
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

func generatePrime(isSafe bool, primeSize int) (*big.Int, *big.Int, error) {
	if isSafe {
		for i := 0; i < maxRetry; i++ {
			safeP, err := utils.GenerateRandomSafePrime(rand.Reader, primeSize)
			if err != nil {
				return nil, nil, err
			}
			safeQ, err := utils.GenerateRandomSafePrime(rand.Reader, primeSize)
			if err != nil {
				return nil, nil, err
			}
			p := new(big.Int).Set(safeP.P)
			q := new(big.Int).Set(safeQ.P)

			// Because the bit length of p and q are the same and p!= q, GCD(p, q)=1.
			if p.Cmp(q) == 0 {
				continue
			}
			return p, q, nil
		}
		return nil, nil, ErrExceedMaxRetry
	}
	for i := 0; i < maxRetry; i++ {
		p, err := rand.Prime(rand.Reader, primeSize)
		if err != nil {
			return nil, nil, err
		}
		q, err := rand.Prime(rand.Reader, primeSize)
		if err != nil {
			return nil, nil, err
		}

		// Because the bit length of p and q are the same and p!= q, GCD(p, q)=1.
		if p.Cmp(q) == 0 {
			continue
		}
		return p, q, nil
	}
	return nil, nil, ErrExceedMaxRetry
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
func getGAndMuWithSpecialG(lambda *big.Int, n *big.Int) (*big.Int, *big.Int, error) {
	nSquare := new(big.Int).Mul(n, n) // n^2
	for i := 0; i < maxGenG; i++ {
		g := new(big.Int).Add(big1, n)            // g
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

func (p *Paillier) GetNthRoot() (*big.Int, error) {
	eulerValue, err := utils.EulerFunction([]*big.Int{p.privateKey.p, p.privateKey.q})
	if err != nil {
		return nil, err
	}
	return new(big.Int).ModInverse(p.n, eulerValue), nil
}
