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
	"math"
	"math/big"

	"github.com/getamis/alice/crypto/elliptic"

	bqForm "github.com/getamis/alice/crypto/binaryquadraticform"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	zkproof "github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/proto"
)

const (
	// This value corresponds to the security level 112.
	minimalSecurityLevel = 1348
	// minimal bit-Length of message size (P.13 Linearly Homomorphic Encryption from DDH)
	minimalBitLengthMessageSpace = 80

	// maxGenG defines the max retries to generate g
	maxGenG = 100
)

var (
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big3 = big.NewInt(3)
	big4 = big.NewInt(4)

	// a list of small primes
	smallPrimeList = []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107}

	//ErrSmallSafeParameter is returned if SafeParameter /2 < the big-length of messagespace + 2
	ErrSmallSafeParameter = errors.New("small safe parameter")
	//ErrNoSplittingPrime is returned if we can not find any split prime in the list.
	//We can find any split prime in primeList, the possibility is 1 / 2^(len(primeList)).
	ErrNoSplittingPrime = errors.New("no splittable primes")
	//ErrFailedVerify is returned if we verify failed
	ErrFailedVerify = errors.New("failed verify")
	//ErrFailedGenerateG is returned if g is the identity element
	ErrFailedGenerateG = errors.New("failed generate non-identity g")
	//ErrNotBigPrime is returned if p is not a big prime
	ErrNotBigPrime = errors.New("not a big prime")
)

/*
 * Paper: Linearly Homomorphic Encryption from DDH & Bandwidth-efficient threshold EC-DSA
 * s : an upper bound of 1/π(ln|ΔK|)|ΔK|^(1/2) i.e. In this implementation, we set it to be Ceil(1/π(ln|ΔK|))*([|ΔK|^(1/2)]+1).
 * p : message space (μ bits prime)
 * a : s*2^(distributionDistance)
 * o : an element in ideal class group of quadratic order
 * f : a generator of the subgroup of order p of ideal class group of quadratic order
 * g : o^b for some random b in [1,2^(distributionDistance)*s)
 * h : g^x, where x is the chosen private key, h is the public key
 Note: a = s*2^(40), d = 40, C = 1024.
*/
type PublicKey struct {
	p     *big.Int // message space
	q     *big.Int
	a     *big.Int
	g     bqForm.Exper
	f     bqForm.Exper
	h     bqForm.Exper
	d     uint32
	c     *big.Int
	proof *ProofMessage

	// cache value
	discriminantOrderP *big.Int
}

type privateKey struct {
	x *big.Int // private key: x
}

type CL struct {
	*PublicKey
	privateKey *privateKey
}

// NewCL news the cl crypto.
// Please refer the following paper Fig. 2 for the key generation flow.
// https://pdfs.semanticscholar.org/fba2/b7806ea103b41e411792a87a18972c2777d2.pdf?_ga=2.188920107.1077232223.1562737567-609154886.1559798768
func NewCL(c *big.Int, d uint32, p *big.Int, safeParameter int, distributionDistance uint) (*CL, error) {
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

	privkey, err := utils.RandomInt(a)
	if err != nil {
		return nil, err
	}
	// Build public key
	h, err := g.Exp(privkey)
	if err != nil {
		return nil, err
	}
	// Build public key zk proof
	proof, err := newPubKeyProof(privkey, a, c, p, q, g, f, h)
	if err != nil {
		return nil, err
	}

	publicKey, err := newPubKey(proof, d, discirminantP, a, c, p, q, g, f, h)
	if err != nil {
		return nil, err
	}
	privateKey := &privateKey{
		x: privkey,
	}
	return &CL{
		PublicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// Encrypt is used to encrypt message
func (publicKey *PublicKey) Encrypt(data []byte) ([]byte, error) {
	// Pick r in {0, ..., A-1} randomly
	r, err := utils.RandomInt(publicKey.a)
	if err != nil {
		return nil, err
	}
	// Compute c1 = g^r
	c1, err := publicKey.g.Exp(r)
	if err != nil {
		return nil, err
	}

	// Compute c2 = f^m*h^r
	message := new(big.Int).SetBytes(data)
	// Check message in [0,p-1]
	err = utils.InRange(message, big0, publicKey.p)
	if err != nil {
		return nil, err
	}
	c2, err := publicKey.f.Exp(message)
	if err != nil {
		return nil, err
	}

	// h^r
	hPower, err := publicKey.h.Exp(r)
	if err != nil {
		return nil, err
	}
	c2, err = c2.Composition(hPower)
	if err != nil {
		return nil, err
	}

	// build proof
	proof, err := publicKey.buildProof(message, r)
	if err != nil {
		return nil, err
	}
	msg := &EncryptedMessage{
		M1:    c1.ToMessage(),
		M2:    c2.ToMessage(),
		Proof: proof,
	}
	return proto.Marshal(msg)
}

// Add represents homomorphic addition
func (publicKey *PublicKey) Add(m1 []byte, m2 []byte) ([]byte, error) {
	c11, c12, err := newBQs(publicKey.discriminantOrderP, m1)
	if err != nil {
		return nil, err
	}
	c21, c22, err := newBQs(publicKey.discriminantOrderP, m2)
	if err != nil {
		return nil, err
	}

	form1, err := c11.Composition(c21)
	if err != nil {
		return nil, err
	}
	form2, err := c12.Composition(c22)
	if err != nil {
		return nil, err
	}

	r, err := utils.RandomInt(publicKey.a)
	if err != nil {
		return nil, err
	}
	gPower, err := publicKey.g.Exp(r)
	if err != nil {
		return nil, err
	}
	hPower, err := publicKey.h.Exp(r)
	if err != nil {
		return nil, err
	}

	form1, err = form1.Composition(gPower)
	if err != nil {
		return nil, err
	}
	form2, err = form2.Composition(hPower)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(&EncryptedMessage{
		M1: form1.ToMessage(),
		M2: form2.ToMessage(),
	})
}

// MulConst multiplies an encrypted integer with a constant
func (publicKey *PublicKey) MulConst(m1 []byte, constant *big.Int) ([]byte, error) {
	// c1' := c1^constant, c2' := c2^constant
	constantMod := new(big.Int).Mod(constant, publicKey.p)
	c1, c2, err := newBQs(publicKey.discriminantOrderP, m1)
	if err != nil {
		return nil, err
	}
	c1, err = c1.Exp(constantMod)
	if err != nil {
		return nil, err
	}
	c2, err = c2.Exp(constantMod)
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomInt(publicKey.a)
	if err != nil {
		return nil, err
	}
	// g^r and h^r
	gPower, err := publicKey.g.Exp(r)
	if err != nil {
		return nil, err
	}

	hPower, err := publicKey.h.Exp(r)
	if err != nil {
		return nil, err
	}

	// c1' * g^r, c2' * h^r
	c1, err = c1.Composition(gPower)
	if err != nil {
		return nil, err
	}
	c2, err = c2.Composition(hPower)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(&EncryptedMessage{
		M1: c1.ToMessage(),
		M2: c2.ToMessage(),
	})
}

func (publicKey *PublicKey) GetMessageRange(fieldOrder *big.Int) *big.Int {
	return new(big.Int).Set(fieldOrder)
}

func (publicKey *PublicKey) ToPubKeyMessage() *PubKeyMessage {
	return &PubKeyMessage{
		P:     publicKey.p.Bytes(),
		A:     publicKey.a.Bytes(),
		Q:     publicKey.q.Bytes(),
		G:     publicKey.g.ToMessage(),
		F:     publicKey.f.ToMessage(),
		H:     publicKey.h.ToMessage(),
		C:     publicKey.c.Bytes(),
		D:     publicKey.d,
		Proof: publicKey.proof,
	}
}

func (publicKey *PublicKey) ToPubKeyBytes() []byte {
	bs, _ := proto.Marshal(publicKey.ToPubKeyMessage())
	return bs
}

// Decrypt computes the plaintext from the ciphertext
func (c *CL) Decrypt(data []byte) ([]byte, error) {
	// Ensure M1 and M2 is valid
	ciphertext1, ciphertext2, err := newBQs(c.discriminantOrderP, data)
	if err != nil {
		return nil, err
	}

	// Compute c1^(-x)
	c1Inverse := ciphertext1.Inverse()
	c1Power, err := c1Inverse.Exp(c.privateKey.x)
	if err != nil {
		return nil, err
	}

	// c2/c1^x and Parse Red(X) as (p^2, xp)
	// Solve(p, g, f, G, F, M)
	message, err := ciphertext2.Composition(c1Power)
	if err != nil {
		return nil, err
	}
	result := message.GetB()
	// Get x
	result.Div(result, c.p)
	// Compute x^(-1) mod p
	result.ModInverse(result, c.p)
	return result.Bytes(), nil
}

func (c *CL) GetPubKey() homo.Pubkey {
	return c.PublicKey
}

func (pubKey *PublicKey) GetPubKeyProof() *ProofMessage {
	return pubKey.proof
}

func (c *CL) GetMtaProof(curve elliptic.Curve, beta *big.Int, b *big.Int) ([]byte, error) {
	proofMsgB, err := zkproof.NewBaseSchorrMessage(curve, b)
	if err != nil {
		return nil, err
	}
	betaModOrder := new(big.Int).Mod(beta, curve.Params().N)
 	proofMsgBeta, err := zkproof.NewBaseSchorrMessage(curve, betaModOrder)
	if err != nil {
		return nil, err
	}
	proofMsg := &VerifyMtaMessage{
		ProofBeta: proofMsgBeta,
 		ProofB:    proofMsgB,
	}
	return proto.Marshal(proofMsg)
}

func (c *CL) VerifyMtaProof(bs []byte, curve elliptic.Curve, alpha *big.Int, k *big.Int) (*pt.ECPoint, error) {
	msg := &VerifyMtaMessage{}
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
	alphaG := pt.ScalarBaseMult(curve, alpha)
	compare := B.ScalarMult(k)
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

func (c *CL) NewPubKeyFromBytes(bs []byte) (homo.Pubkey, error) {
	msg := &PubKeyMessage{}
	err := proto.Unmarshal(bs, msg)
	if err != nil {
		return nil, err
	}
	return msg.ToPubkey()
}

// Find a prime r such that (ΔK/r) = 1
func generateR(discriminantK *big.Int) (*big.Int, error) {
	for i := 0; i < len(smallPrimeList); i++ {
		prime := new(big.Int).SetUint64(smallPrimeList[i])
		jacobi := big.Jacobi(discriminantK, prime)
		if jacobi == 1 {
			return prime, nil
		}
	}
	return nil, ErrNoSplittingPrime
}

// Let p be a split prime in the ring of integer. Find an above prime of p in the maximal order
// of Q(D^{1/2}). The formula is given by (p, -b, c) with Discriminant = b^2 - 4pc, where b^2 = D mod 4p
// ref: Prop 5.1.4, A Course in Computational Algebraic Number theory, Cohen GTM 138.
func generateLyingAbovePrime(discriminant, prime *big.Int) (*bqForm.BQuadraticForm, error) {
	squareSolutionModp := new(big.Int).ModSqrt(discriminant, prime)
	// solution is 1
	tp := new(big.Int).ModInverse(big4, prime)
	t4 := new(big.Int).ModInverse(prime, big4)
	// Mptp = 1 mod 4 and M4t4 =1 mod prime
	Mptp := new(big.Int).Lsh(tp, 2)
	M4t4 := new(big.Int).Mul(prime, t4)
	solution := new(big.Int).Mul(squareSolutionModp, Mptp)
	solution.Add(solution, M4t4)
	solution.Mod(solution, new(big.Int).Lsh(prime, 2))
	return bqForm.NewBQuadraticFormByDiscriminant(prime, solution.Neg(solution), discriminant)
}

// The formula is given in the step 6 of Fig 2. A new DDH Group with an Easy DL Subgroup.
// ref: Linearly Homomorphic Encryption from DDH
func generateGeneratorInG(rForm *bqForm.BQuadraticForm, f *bqForm.BQuadraticForm, p *big.Int) (*bqForm.BQuadraticForm, error) {
	// Root4thDiscriminantOrderp = p^(1/2) * Root4thDiscriminant
	rFormSquare, err := rForm.Exp(big2)
	if err != nil {
		return nil, err
	}

	// k in in {1, p-1}
	k, err := utils.RandomPositiveInt(p)
	if err != nil {
		return nil, err
	}

	// Get the lift value n of the split prime.
	liftPrimePpPower, err := liftElement(rFormSquare, p, f.GetDiscriminant())
	if err != nil {
		return nil, err
	}
	// Compute f^k
	fkPower, err := f.Exp(k)
	if err != nil {
		return nil, err
	}
	// Compute n^p * f^k
	g, err := liftPrimePpPower.Composition(fkPower)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// The formula is [a, Bp mod 2a] ref: Nice-New Ideal Coset Encryption:Algorithm 2
func liftElement(form *bqForm.BQuadraticForm, messageSpace *big.Int, discriminantP *big.Int) (*bqForm.BQuadraticForm, error) {
	a := new(big.Int).Set(form.GetA())
	// 2a
	doubleA := new(big.Int).Lsh(a, 1)
	// Bp mod 2a
	b := new(big.Int).Set(form.GetB())
	b.Mul(b, messageSpace)
	b.Mod(b, doubleA)
	return bqForm.NewBQuadraticFormByDiscriminant(a, b, discriminantP)
}

// Cl(O_K) < 1/π(ln|ΔK|)|ΔK|^(1/2) ref. Brauer–Siegel theorem
// Compute the value of Ceil(1/π(ln|ΔK|))*([|ΔK|^(1/2)]+1)
func getUpperBoundClassGroupMaximalOrder(discriminant *big.Int) *big.Int {
	absdiscriminant := new(big.Int).Abs(discriminant)
	sqrt := new(big.Int).Sqrt(absdiscriminant)
	upperBound := new(big.Int).Add(sqrt, big1)

	// ln|ΔK| = (bit-Length(ΔK))*ln(2)
	logDiscriminantOverPi := float64(absdiscriminant.BitLen()) * math.Log(2.0)
	// the ceiling value of [ln|ΔK|/π].
	logDiscriminantOverPi = math.Ceil(logDiscriminantOverPi / math.Pi)
	upperBoundlogDiscriminantOverPi := new(big.Int).SetInt64(int64(logDiscriminantOverPi))
	upperBound = upperBound.Mul(upperBound, upperBoundlogDiscriminantOverPi)
	return upperBound
}

// generateAnotherPrimeQ returns the a q such that the discriminant is -pq.
func generateAnotherPrimeQ(p *big.Int, bitsQ int) (*big.Int, error) {
	// Get a prime q which satisfies
	// 1. p*q = 3 mod 4
	// 2. Jacobi(p, q)= -1
	// the length of Bit(q) = bitsQ.
	for {
		q, err := utils.RandomPrime(bitsQ)
		if err != nil {
			return nil, err
		}
		pq := new(big.Int).Mul(q, p)
		pqMod4 := new(big.Int).And(pq, big3)
		if pqMod4.Cmp(big3) != 0 {
			continue
		}
		if big.Jacobi(p, q) != -1 {
			continue
		}

		// Compute (|ΔK/4|)^(1/4)
		// The value is used for computing composition and exp of binary quadratic forms.
		return q, nil
	}
}

func getNonIdentityGenerator(generator *bqForm.BQuadraticForm, upperBound *big.Int) (*bqForm.BQuadraticForm, error) {
	identity := generator.Identity()
	for i := 0; i < maxGenG; i++ {
		b, err := utils.RandomPositiveInt(upperBound)
		if err != nil {
			return nil, err
		}
		g, err := generator.Exp(b)
		if err != nil {
			return nil, err
		}
		if !g.Equal(identity) {
			return g, nil
		}
	}
	return nil, ErrFailedGenerateG
}
