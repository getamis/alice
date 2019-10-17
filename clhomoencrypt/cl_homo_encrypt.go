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

package clhomoencrypt

import (
	"crypto/rand"
	"errors"
	"math/big"

	bqForm "github.maicoin.site/amis/research/binaryQuadraticForm"
)

var (
	bigOne   = big.NewInt(1)
	bigTwo   = big.NewInt(2)
	bigThree = big.NewInt(3)
	bigFour  = big.NewInt(4)

	// a list of primes
	PrimeList = [16]uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 53, 59}

	// SafeParameter /2 >= the big-length of messagespace + 2
	ErrSmallSafeParameter = errors.New("Small SafeParameter!")

	// We can find any split prime in PrimeList, the possibility is 1 / 2^(len(PrimeList)).
	ErrNoSplittingPrime = errors.New("Not Find any Split Prime in the List!")
)

/*
 * Paper: Linearly Homomorphic Encryption from DDH
 * B: ceiling value of |ΔK|^(3/4) (referenced by the paper on page 12)
 * p: message space (μ bits prime)
 * BP: B*p
 * g : an element in ideal class group of quadratic order
 * f : a generator of the subgroup of order p of ideal class group of quadratic order
 * h : g^x, where x is the chosen private key, h is the public key
 */
type PublicKey struct {
	B                         *big.Int
	p                         *big.Int // message space
	BP                        *big.Int
	root4thDiscriminantK      *big.Int
	root4thDiscriminantOrderP *big.Int

	g *bqForm.BQuadraticForm
	f *bqForm.BQuadraticForm
	h *bqForm.BQuadraticForm
}

type PrivateKey struct {
	x                         *big.Int // private key: x
	p                         *big.Int
	root4thDiscriminantOrderP *big.Int
}

type CipherMessege struct {
	m1 *bqForm.BQuadraticForm
	m2 *bqForm.BQuadraticForm
}

// GenerateRandomInt generates a random number in [0, n)
func GenerateRandomInt(N *big.Int) *big.Int {
	r, _ := rand.Int(rand.Reader, N)

	return r
}

// GeneratePositiveRandom generates a random number in [1, n)
func GeneratePositiveRandom(N *big.Int) *big.Int {
	nMinusOne := new(big.Int).Sub(N, bigOne)
	r, _ := rand.Int(rand.Reader, nMinusOne)

	return new(big.Int).Add(r, bigOne)
}

// PubKeygen generates a pair of private/public key. The definition of safeParameter is the fundamental discriminant ΔK.
func PubKeygen(messageSpace *big.Int, safeParameter int) (*PublicKey, *PrivateKey, error) {
	lambda := safeParameter / 2

	// λ ≥ μ + 2
	if lambda < messageSpace.BitLen()+2 {
		return nil, nil, ErrSmallSafeParameter
	}
	bitLengthQprime := safeParameter - messageSpace.BitLen()
	
	discriminantK := generateAbsDiscriminantK(messageSpace, bitLengthQprime)

	// Compute (ΔK/4)^(1/4)
	// The value is used for computing composition and exp of binary quadratic forms.
	discriminantKOVer4 := new(big.Int).Rsh(discriminantK, 2)
	discriminantKOVer4 = new(big.Int).Sqrt(discriminantKOVer4)
	root4thDiscriminantK := new(big.Int).Sqrt(discriminantKOVer4)

	// ΔK = -p * q
	discriminantK.Neg(discriminantK)

	// ΔP = p^2 * ΔK
	messageSquare := new(big.Int).Mul(messageSpace, messageSpace)
	discirminantP := new(big.Int).Mul(messageSquare, discriminantK)

	// Root4thDiscriminantOrderp = p^(1/2) * Root4thDiscriminant
	messageSqrt := new(big.Int).Sqrt(messageSpace)
	root4thDiscriminantOrderP := new(big.Int).Mul(root4thDiscriminantK, messageSqrt)

	// f = (p^2, p)
	fa := new(big.Int).Set(messageSquare)
	fb := new(big.Int).Set(messageSpace)

	f, err := bqForm.NewBQuadraticFormByDiscriminant(fa, fb, discirminantP)

	if err != nil {
		return nil, nil, err
	}

	// Generate split prime in the maximal order Q(ΔK^(1/2))
	splitPrime, err := generateSplitPrime(discriminantK, messageSpace)

	if err != nil {
		return nil, nil, err
	}

	// Get lying above prime hat{r}
	rForm := generateLyingAbovePrime(discriminantK, splitPrime)

	// Compute hat{r}^2
	rFormSquare := rForm.Exp(bigTwo, root4thDiscriminantK)

	// Compute g by the lifing formula
	g := generateGeneratorInG(messageSpace, rFormSquare, f, root4thDiscriminantOrderP)

	// B = the ceil value of |ΔK|^(3/4)
	B := getDiscriminantPower3Over4(discriminantK)

	if err != nil {
		return nil, nil, err
	}

	BP := new(big.Int).Mul(messageSpace, B)
	privkey := GenerateRandomInt(BP)

	h := g.Exp(privkey, root4thDiscriminantOrderP)

	publicKey := &PublicKey{
		B:                         B,
		p:                         messageSpace,
		BP:                        BP,
		g:                         g,
		f:                         f,
		h:                         h,
		root4thDiscriminantK:      root4thDiscriminantK,
		root4thDiscriminantOrderP: root4thDiscriminantOrderP,
	}

	privateKey := &PrivateKey{
		x:                         privkey,
		p:                         messageSpace,
		root4thDiscriminantOrderP: root4thDiscriminantOrderP,
	}

	return publicKey, privateKey, nil
}

// Encrypt is used to encrypt message
func Encrypt(publicKey *PublicKey, message *big.Int) *CipherMessege {
	// Pick r in {0, ..., Bp-1} randomly
	r := GenerateRandomInt(publicKey.BP)

	// Compute c1 = g^r
	c1 := publicKey.g.Exp(r, publicKey.root4thDiscriminantOrderP)

	// Compute c2 = f^m*h^r, f^m
	// f^m
	c2 := publicKey.f.Exp(message, publicKey.root4thDiscriminantOrderP)
	// h^r
	hPower := publicKey.h.Exp(r, publicKey.root4thDiscriminantOrderP)
	c2 = c2.Composition(hPower, publicKey.root4thDiscriminantOrderP)

	return &CipherMessege{
		m1: c1,
		m2: c2,
	}
}

// Decrypt computes the plaintext from the ciphertext
func Decrypt(cipherMessage *CipherMessege, privateKey *PrivateKey) *big.Int {
	ciphertext1 := cipherMessage.m1
	ciphertext2 := cipherMessage.m2

	// Compute c1^(-x)
	c1Inverse := ciphertext1.Inverse()
	c1Power := c1Inverse.Exp(privateKey.x, privateKey.root4thDiscriminantOrderP)

	// c2/c1^x and Parse Red(X) as (p^2, xp)
	// Solve(p, g, f, G, F, M)
	message := ciphertext2.Composition(c1Power, privateKey.root4thDiscriminantOrderP)
	result := message.GetBQFormb()

	// Get x
	result.Div(result, privateKey.p)

	// Compute x^(-1) mod p
	result.ModInverse(result, privateKey.p)
	return result
}

// EvalAdd represents homomorphic addition
func EvalAdd(message1 *CipherMessege, message2 *CipherMessege, publicKey *PublicKey) *CipherMessege {
	form1 := message1.m1.Composition(message2.m1, publicKey.root4thDiscriminantOrderP)
	form2 := message1.m2.Composition(message2.m2, publicKey.root4thDiscriminantOrderP)

	r := GenerateRandomInt(publicKey.BP)

	gPower := publicKey.g.Exp(r, publicKey.root4thDiscriminantOrderP)
	hPower := publicKey.h.Exp(r, publicKey.root4thDiscriminantOrderP)

	form1 = form1.Composition(gPower, publicKey.root4thDiscriminantOrderP)
	form2 = form2.Composition(hPower, publicKey.root4thDiscriminantOrderP)

	return &CipherMessege{
		m1: form1,
		m2: form2,
	}
}

// EvalMulConst multiplies an encrypted integer with a constant
func EvalMulConst(message *CipherMessege, constant *big.Int, publicKey *PublicKey) *CipherMessege {
	// c1' := c1^constant, c2' := c2^constant
	form1 := message.m1.Copy()
	form1 = form1.Exp(constant, publicKey.root4thDiscriminantOrderP)

	form2 := message.m2.Copy()
	form2 = form2.Exp(constant, publicKey.root4thDiscriminantOrderP)

	r := GenerateRandomInt(publicKey.BP)

	// g^r and h^r
	gPower := publicKey.g.Exp(r, publicKey.root4thDiscriminantK)
	hPower := publicKey.h.Exp(r, publicKey.root4thDiscriminantOrderP)

	// c1' * g^r, c2' * h^r
	form1 = form1.Composition(gPower, publicKey.root4thDiscriminantOrderP)
	form2 = form2.Composition(hPower, publicKey.root4thDiscriminantOrderP)

	return &CipherMessege{
		m1: form1,
		m2: form2,
	}
}

// Find a prime p such that (D/p) = 1, where D is the discriminant and (*/*) is the Kronecker symbol.
// Given any prime p, the possibility of p with (D/p) = 1 is 1/2. Therefore, we establish a list of prime integers
// to compute the lifting of a splitting prime.
func generateSplitPrime(discriminant, messageSpace *big.Int) (*big.Int, error) {
	for i := 0; i < len(PrimeList); i++ {
		prime := new(big.Int).SetUint64(PrimeList[i])
		jacobi := big.Jacobi(discriminant, prime)

		if jacobi == 1 {
			return prime, nil
		}
	}

	return nil, ErrNoSplittingPrime
}

// Let p be a split prime in the ring of integer. Find an above prime of p in the maximal order
// of Q(D^{1/2}). The formula is given by (p,-b,c) with Discriminant = b^2 - 4pc, where b^2 = D mod 4p
// ref: Prop 5.1.4, A Course in Computational Algebraic Number theory, Cohen GTM 138.
func generateLyingAbovePrime(discriminant, prime *big.Int) *bqForm.BQuadraticForm {
	squareSolutionModp := new(big.Int).ModSqrt(discriminant, prime)
	// solution is 1
	tp := new(big.Int).ModInverse(bigFour, prime)
	t4 := new(big.Int).ModInverse(prime, bigFour)

	// Mptp = 1 mod 4 and M4t4 =1 mod prime
	Mptp := new(big.Int).Lsh(tp, 2)
	M4t4 := new(big.Int).Mul(prime, t4)

	solution := new(big.Int).Mul(squareSolutionModp, Mptp)
	solution.Add(solution, M4t4)
	solution.Mod(solution, new(big.Int).Lsh(prime, 2))

	bq, _ := bqForm.NewBQuadraticFormByDiscriminant(prime, solution.Neg(solution), discriminant)
	bq.Reduction()

	return bq
}

// The formula is given in the step 6 of Fig 2. A new DDH Group with an Easy DL Subgroup.
// ref: Linearly Homomorphic Encryption from DDH
func generateGeneratorInG(messageSpace *big.Int, splitPrimeSquare *bqForm.BQuadraticForm,
	f *bqForm.BQuadraticForm, Root4thDiscriminantOrderp *big.Int) *bqForm.BQuadraticForm {
	// k in in {1,p-1}
	k := GeneratePositiveRandom(messageSpace)

	// Get the lift value n of the split prime.
	liftPrimePpPower := liftElement(splitPrimeSquare, messageSpace, f.GetBQFormDiscriminant())

	// Compute n^p
	liftPrimePpPower.Exp(messageSpace, Root4thDiscriminantOrderp)

	// Compute f^k
	fkPower := f.Exp(k, Root4thDiscriminantOrderp)

	// Compute n^p * f^k
	g := liftPrimePpPower.Composition(fkPower, Root4thDiscriminantOrderp)

	return g
}

// The formula is [a,Bp mod 2a] ref: Nice-New Ideal Coset Encryption:Algorithm 2
func liftElement(form *bqForm.BQuadraticForm, messageSpace *big.Int, discriminantP *big.Int) *bqForm.BQuadraticForm {
	a := new(big.Int).Set(form.GetBQForma())

	// 2a
	doubleA := new(big.Int).Lsh(a, 1)

	// Bp mod 2a
	b := new(big.Int).Set(form.GetBQFormb())
	b.Mul(b, messageSpace)
	b.Mod(b, doubleA)
	result, _ := bqForm.NewBQuadraticFormByDiscriminant(a, b, discriminantP)

	return result
}

// The out is [ discriminant^(3/4) ]
func getDiscriminantPower3Over4(discriminant *big.Int) *big.Int {
	Absdiscriminant := new(big.Int).Abs(discriminant)
	sqrtsqrt := new(big.Int).Sqrt(Absdiscriminant)
	sqrtsqrt = sqrtsqrt.Sqrt(sqrtsqrt)

	upperBound := new(big.Int).Div(Absdiscriminant, sqrtsqrt)

	return upperBound
}

// generateAbsDiscriminantK returns |ΔK|
func generateAbsDiscriminantK(messageSpace *big.Int, bitLengthQprime int) *big.Int {
	// Generate a prime q
	cofactorPrime, _ := rand.Prime(rand.Reader, bitLengthQprime)

	// Compute p*q (p: a random μ-bits prime)
	qMulp := new(big.Int).Mul(cofactorPrime, messageSpace)

	// Check p*q = 3 mod 4
	qMulpMod4 := new(big.Int).And(qMulp, bigThree)

	// Compute Jacobi(p, q)
	jacobiValue := big.Jacobi(messageSpace, cofactorPrime)

	// Get a prime q which satisfies
	// 1. p*q = 3 mod 4
	// 2. Jacobi(p, q)= -1
	// the length of Bit(q) = bitLengthQprime.
	for qMulpMod4.Cmp(bigThree) != 0 || jacobiValue != -1 {
		cofactorPrime, _ = rand.Prime(rand.Reader, bitLengthQprime)
		qMulp = new(big.Int).Mul(cofactorPrime, messageSpace)
		qMulpMod4 = new(big.Int).And(qMulp, bigThree)
		jacobiValue = big.Jacobi(messageSpace, cofactorPrime)
	}

	return qMulp
}
