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

package binaryquadraticform

import (
	"errors"
	"math/big"
)

var (
	bigZero = big.NewInt(0)
	bigOne = big.NewInt(1)
	bigTwo = big.NewInt(2)
	bigThree = big.NewInt(3)

	GMP_LIMB_BITS = 64

	// Recommend 4. This value should be a power of 2. This value should be smaller than 32.
	NUMBERNODE = 8

	// In this library, we only consider positive definite quadratic forms
	ErrPositiveDiscriminant = errors.New("Discriminant Should be Negative")
)

/* This Library only supports some oprations of "pimitive positive definite binary quadratic forms" (i.e.
 * corresponding to ideal operations over imaginary quadratic fields).
 * A Quadratic form is given by: (a,b,c) := ax^2+bxy+cy^2 with discriminant = b^2 - 4ac < 0
 */
type BQuadraticForm struct {
	a            *big.Int
	b            *big.Int
	c            *big.Int
	discriminant *big.Int
}

// "Constructor:"
// Give a number N, assume that N = 2^exponent2 * 3^exponent * others. Sign = 1 or -1.
type expansion23 struct {
	exponent2 int
	exponent3 int
	sign      int
}

// Give a, b, discriminant to constuct quadratic forms.
func Newexpansion23(exponent2, exponent3, s int) *expansion23 {

	return &expansion23{
		exponent2: exponent2,
		exponent3: exponent3,
		sign:      s,
	}
}

// Give a, b, c to construct quadratic forms.
func NewBQuadraticForm(a, b, c *big.Int) (*BQuadraticForm, error) {

	// discriminant = b^2 - 4ac
	discriminant := new(big.Int).Mul(b, b)
	ac := new(big.Int).Mul(a, c)
	discriminant = discriminant.Sub(discriminant, ac.Lsh(ac, 2))

	if discriminant.Sign() > -1 {
		return nil, ErrPositiveDiscriminant
	}

	return &BQuadraticForm{
		a:            a,
		b:            b,
		c:            c,
		discriminant: discriminant,
	}, nil
}

// Give a, b, discriminant to constuct quadratic forms.
func NewBQuadraticFormByDiscriminant(a, b, discriminant *big.Int) (*BQuadraticForm, error) {
	if discriminant.Sign() > -1 {
		return nil, ErrPositiveDiscriminant
	}

	bSquare := new(big.Int).Mul(b, b)
	c := new(big.Int).Sub(bSquare, discriminant)
	c.Div(c, a)
	c.Rsh(c, 2)

	return &BQuadraticForm{
		a:            a,
		b:            b,
		c:            c,
		discriminant: discriminant,
	}, nil
}

// Reduction of Positive Difinite Forms: Given a positive definite quadratic form f = (a,b,c)
// of discriminant D = b^2 -4ac < 0, this algorithm ouputs the unique reduced form equivalent
// to f. cf: Algorithm 5.4.2, A Course in Computational Algebraic Number theory, Cohen GTM 138.
func (bqForm *BQuadraticForm) Reduction() {

	CopyNega := new(big.Int).Neg(bqForm.a)

	// if -a < b <= a
	if bqForm.b.Cmp(CopyNega) == 1 && bqForm.b.Cmp(bqForm.a) <= 0 {
		bqForm.reductionMainStep()
		return
	}

	bqForm.euclideanStep()
	bqForm.reductionMainStep()
	return
}
 
// Note that: D < 0. (a,b,c) is reduced if |b| <= a <= c and if b >= 0 whenever
// a = |b| or a = c
func (bqForm *BQuadraticForm) IsReducedForm() bool {

	absoluteB := new(big.Int).Abs(bqForm.b)

	// |b| < a < c
	if bqForm.a.Cmp(absoluteB) > 0 && bqForm.c.Cmp(bqForm.a) > 0 {
		return true
	}

	// a = |b| and b >= 0
	if bqForm.a.Cmp(absoluteB) == 0 && bqForm.b.Cmp(bigZero) > -1 {
		return true
	}

	// a = c and b >= 0
	if bqForm.a.Cmp(bqForm.c) == 0 && bqForm.b.Cmp(bigZero) > -1 {
		return true
	}
	return false
}

// Get the coefficient of a binary quadratic form: ax^2 + bxy + cy^2
// Get a
func (bqForm *BQuadraticForm) GetBQForma() *big.Int {
	return bqForm.a
}

// Get b
func (bqForm *BQuadraticForm) GetBQFormb() *big.Int {
	return bqForm.b
}

// Get c
func (bqForm *BQuadraticForm) GetBQFormc() *big.Int {
	return bqForm.c
}

// Get discriminant
func (bqForm *BQuadraticForm) GetBQFormDiscriminant() *big.Int {
	return bqForm.discriminant
}

// The inverse quadratic Form of [a,b,c] is [a,-b,c]
func (bqForm *BQuadraticForm) Inverse() *BQuadraticForm {
	result := bqForm.Copy()
	result.b.Neg(result.b)
	result.Reduction()
	return result
}

// Identity element := bqForm * bqForm.Inverse()
func (bqForm *BQuadraticForm) Identity(Droot4th *big.Int) *BQuadraticForm {
	bqFormInverse := bqForm.Copy()
	bqFormInverse = bqFormInverse.Inverse()
	result := bqForm.Composition(bqFormInverse, Droot4th)
	return result
}

/* The composition operation of binary quadratic forms
 * NUCOMP algorithm. Adapted from "Solving the Pell Equation"
 * by Michael J. Jacobson, Jr. and Hugh C. Williams.
 * http://www.springer.com/mathematics/numbers/book/978-0-387-84922-5
 * The code original authur : Maxwell Sayles.
 * Code: https://github.com/maxwellsayles/libqform/blob/master/mpz_qform.c
 */
func (bqForm *BQuadraticForm) Composition(inputForm *BQuadraticForm, Droot4th *big.Int) *BQuadraticForm {

	a1 := new(big.Int).Set(bqForm.a)
	b1 := new(big.Int).Set(bqForm.b)
	a2 := new(big.Int).Set(inputForm.a)
	b2 := new(big.Int).Set(inputForm.b)
	c2 := new(big.Int).Set(inputForm.c)

	if a1.Cmp(a2) < 0 {
		a1 = new(big.Int).Set(inputForm.a)
		b1 = new(big.Int).Set(inputForm.b)
		a2 = new(big.Int).Set(bqForm.a)
		b2 = new(big.Int).Set(bqForm.b)
		c2 = new(big.Int).Set(bqForm.c)
	}

	ss := new(big.Int).Add(b1, b2)
	ss.Rsh(ss, 1)

	m := new(big.Int).Sub(b1, b2)
	m.Rsh(m, 1)

	v1, _, SP := exGCD(a2, a1)

	K := new(big.Int).Mul(m, v1)
	K.Mod(K, a1)

	var u2, v2, S *big.Int

	if SP.Cmp(bigOne) != 0 {
		u2, v2, S = exGCD(SP, ss)

		K.Mul(K, u2)
		tempValue := new(big.Int).Mul(v2, c2)
		K.Sub(K, tempValue)

		if S.Cmp(bigOne) != 0 {
			a1.Div(a1, S)
			a2.Div(a2, S)
			c2.Mul(c2, S)
		}

		K.Mod(K, a1)
	}

	if a1.Cmp(Droot4th) < 0 {

		T := new(big.Int).Mul(a2, K)

		a := new(big.Int).Mul(a2, a1)

		b := new(big.Int).Lsh(T, 1)
		b.Add(b, b2)

		c := new(big.Int).Add(b2, T)
		c.Mul(c, K)
		c.Add(c, c2)
		c.Div(c, a1)

		result := &BQuadraticForm{
			a:            a,
			b:            b,
			c:            c,
			discriminant: bqForm.discriminant,
		}
		result.Reduction()
		return result
	}

	R2 := new(big.Int).Set(a1)
	R1 := new(big.Int).Set(K)
	C2 := big.NewInt(0)
	C1 := big.NewInt(-1)

	R2, R1, C2, C1 = partialGCD(R2, R1, C2, C1, Droot4th)

	T := new(big.Int).Mul(a2, R1)
	M1 := new(big.Int).Mul(m, C1)
	M1.Add(M1, T)
	M1.Div(M1, a1)

	M2 := new(big.Int).Mul(ss, R1)
	tempValue := new(big.Int).Mul(c2, C1)
	M2.Sub(M2, tempValue)
	M2.Div(M2, a1)

	a := new(big.Int).Mul(R1, M1)
	tempValue = new(big.Int).Mul(C1, M2)
	a.Sub(a, tempValue)

	if C1.Sign() > 0 {
		a.Neg(a)
	}

	b := new(big.Int).Mul(a, C2)
	b.Sub(T, b)
	b.Lsh(b, 1)
	b.Div(b, C1)
	b.Sub(b, b2)
	b.Mod(b, new(big.Int).Lsh(a, 1))

	if a.Sign() < 0 {
		a.Neg(a)
	}

	result, _ := NewBQuadraticFormByDiscriminant(a, b, bqForm.discriminant)
	result.Reduction()
	return result
}

/* The ouput is bqForm ^ power. Ref: Algorithm 3.2, page 30,
 * Improved Arithmetic in the Ideal Class Group of Imaginary
 * Quadratic Number Fields, Maxwell Sayles.
 */
func (bqForm *BQuadraticForm) Exp(power *big.Int, Droot4th *big.Int) *BQuadraticForm {

	expansion := expansion23StrictChains(power, NUMBERNODE)

	R := bqForm.Identity(Droot4th)
	T := bqForm.Copy()

	a, b, index := 0, 0, 0
	for index < len(expansion) {
		for a < expansion[index].exponent2 {
			T = T.square(Droot4th)
			a++
		}

		for b < expansion[index].exponent3 {
			T = T.cube(Droot4th)
			b++
		}

		if expansion[index].sign == 1 {
			R = R.Composition(T, Droot4th)
		} else {
			R = R.Composition(T.Inverse(), Droot4th)
		}
		R.Reduction()
		index++
	}
	return R
}

// copy the binary quadratic form
func (bqForm *BQuadraticForm) Copy() *BQuadraticForm {
	return &BQuadraticForm{
		a:            new(big.Int).Set(bqForm.a),
		b:            new(big.Int).Set(bqForm.b),
		c:            new(big.Int).Set(bqForm.c),
		discriminant: new(big.Int).Set(bqForm.discriminant),
	}
}

// Reduction of Positive definite forms.
func (bqForm *BQuadraticForm) reductionMainStep() {

	for bqForm.IsReducedForm() == false {

		// if a > c, set b = -b and exchange a and c.
		if bqForm.a.Cmp(bqForm.c) > 0 {
			bqForm.b.Neg(bqForm.b)
			bqForm.a, bqForm.c = bqForm.c, bqForm.a

			// if a = c and b < 0, set b = -b
		} else if bqForm.a.Cmp(bqForm.c) == 0 && bqForm.b.Cmp(bigZero) < 0 {
			bqForm.b.Neg(bqForm.b)
		}
		bqForm.euclideanStep()
	}
	return
}

// Euclidean step of Algorithm 5.4.2 : Reduction of Positive definite forms.
func (bqForm *BQuadraticForm) euclideanStep() {

	// Get b = 2aq + r, where 0 <= r < 2a
	var q *big.Int
	r := big.NewInt(0)
	twicea := new(big.Int).Lsh(bqForm.a, 1)
	q, r = new(big.Int).DivMod(bqForm.b, twicea, r)

	// if r > a, set r = r - 2a, and q = (q + 1) ( i.e. we want b = 2aq + r, where -a <= r < a)
	if r.Cmp(bqForm.a) > 0 {
		r.Sub(r, twicea)
		q.Add(q, bigOne)
	}

	// c = c - 1/2(b+r)q, b = r
	bPlusrQ := new(big.Int).Add(bqForm.b, r)
	bPlusrQ.Mul(bPlusrQ, q)
	halfbPlusrQ := new(big.Int).Rsh(bPlusrQ, 1)

	bqForm.c.Sub(bqForm.c, halfbPlusrQ)
	bqForm.b = r
	return
}

/* Extend the GCD in golang. We permit the inputs x, y which can be negative numbers.
 * For inputs x, y, we can find a, b such that ax + by = gcd( |x|, |y| ).
 * In particular, if y = 0, then we return a = sign(x)), b = 0 and gcd = absx.
 */
func exGCD(x, y *big.Int) (*big.Int, *big.Int, *big.Int) {

	absx := new(big.Int).Abs(x)
	absy := new(big.Int).Abs(y)

	if y.Sign() == 0 {
		return new(big.Int).SetInt64(int64(x.Sign())), big.NewInt(0), new(big.Int).Set(absx)
	}

	a, b := big.NewInt(0), big.NewInt(0)
	divisor := new(big.Int).GCD(a, b, absx, absy)

	if x.Sign() == -1 {
		if y.Sign() == -1 {
			return a.Neg(a), b.Neg(b), divisor
		}
		return a.Neg(a), b, divisor

	}

	if y.Sign() == -1 {
		return a, b.Neg(b), divisor
	}
	return a, b, divisor
}

/*
 * The code original authur : Maxwell Sayles.
 * Code: https://github.com/maxwellsayles/libqform/blob/master/mpz_qform.c
 */
func (bqForm *BQuadraticForm) square(Droot4th *big.Int) *BQuadraticForm {

	var a, b *big.Int
	a1 := new(big.Int).Set(bqForm.a)
	b1 := new(big.Int).Set(bqForm.b)
	c1 := new(big.Int).Set(bqForm.c)

	_, v, s := exGCD(a1, b1)

	U := new(big.Int).Mul(v, bqForm.c)
	U.Neg(U)
	
	if s.Cmp(bigOne) != 0 {
		a1.Div(a1,s)
		c1.Mul(c1,s)
	}

	U.Mod(U, a1)

	if a1.Cmp(Droot4th) < 1 {

		T := new(big.Int).Mul(a1,U)

		a = new(big.Int).Mul(a1, a1)

		b := new(big.Int).Lsh(T,1)
		b.Add(b1,b)

		c := new(big.Int).Add(b1,T)
		c.Mul(c,U)
		c.Add(c,c1)
		c.Div(c,a1)

		result:= &BQuadraticForm{
			a:            a,
			b:            b,
			c:            c,
			discriminant: bqForm.discriminant,
		}
		result.Reduction()
		return result
	}

	R2 := new(big.Int).Set(a1)
	R1 := new(big.Int).Set(U)
	C2 := big.NewInt(0)
	C1 := big.NewInt(-1)

	R2, R1, C2, C1 = partialGCD(R2, R1, C2, C1, Droot4th)

	M2 := new(big.Int).Mul(R1, b1)
	tempValue := new(big.Int).Mul(s, C1)
	tempValue.Mul(tempValue, bqForm.c)
	M2.Sub(M2, tempValue)
	M2.Div(M2, a1)

	tempValue = new(big.Int).Mul(R1, R1)
	a = new(big.Int).Mul(C1, M2)
	a.Sub(tempValue, a)

	if C1.Sign() > 0 {
		a.Neg(a)
	}

	b = new(big.Int).Mul(C2, a)
	tempValue = new(big.Int).Mul(R1, a1)
	b.Sub(tempValue, b)
	b.Div(new(big.Int).Lsh(b, 1), C1)
	b.Sub(b, b1)
	b.Mod(b, new(big.Int).Lsh(a, 1))

	if a.Sign() < 0 {
		a.Neg(a)
	}

	result, _ := NewBQuadraticFormByDiscriminant(a, b, bqForm.discriminant)
	result.Reduction()
	return result
}

/*
 * Computes a reduced ideal equivalent to the cube of an ideal.
 * Adapted from "Fast Ideal Cubing in Imaginary Quadratic Number
 * and Function Fields" by Laurent Imbert, Michael J. Jacobson, Jr. and
 * Arthur Schmidt.
 * www.lirmm.fr/~imbert/pdfs/cubing_amc_2010.pdf
 * The code original authur : Maxwell Sayles.
 * Code: https://github.com/maxwellsayles/libqform/blob/master/mpz_qform.c
 */
func (bqForm *BQuadraticForm) cube(Droot4th *big.Int) *BQuadraticForm {

	aModb := new(big.Int).Mod(bqForm.b, bqForm.a)

	if aModb.Sign() == 0 {
		return bqForm
	}

	var S, N, L, K, a, b *big.Int
	c1 := new(big.Int).Set(bqForm.c)

	_, v1, S1 := exGCD(bqForm.a, bqForm.b)

	if S1.Cmp(bigOne) != 0 {

		tempAValue := new(big.Int).Mul(S1, bqForm.a)
		bSquare := new(big.Int).Mul(bqForm.b, bqForm.b)
		tempValue := new(big.Int).Sub(bSquare, bqForm.discriminant)
		tempValue.Rsh(tempValue, 2)
		tempValue.Sub(bSquare, tempValue)

		var u2, v2 *big.Int
		u2, v2, S = exGCD(tempAValue, tempValue)
		N = new(big.Int).Div(bqForm.a, S)
		L = new(big.Int).Mul(N, bqForm.a)

		K = new(big.Int).Mul(v2, bqForm.b)
		K.Mod(K, L)
		tempValue = new(big.Int).Mul(v1, bqForm.a)
		tempValue.Mul(u2, tempValue)
		tempValue.Mod(tempValue, L)
		K.Add(K, tempValue)
		K.Mul(bqForm.c, K)
		K.Neg(K)
		K.Mod(K, L)

		c1.Mul(c1, S)
	} else { 
		S = big.NewInt(1)

		N = new(big.Int).Set(bqForm.a)
		L = new(big.Int).Mul(bqForm.a, bqForm.a)

		tempValue := new(big.Int).Mul(bqForm.a, bqForm.c)
		tempValue.Mod(tempValue, L)
		tempValue.Mul(tempValue, v1)
		tempValue.Mod(tempValue, L)

		tempValue.Sub(bqForm.b, tempValue)
		tempValue.Mul(v1, tempValue)
		tempValue.Sub(tempValue, bigTwo)
		tempValue.Mul(tempValue, v1)
		K = tempValue.Mul(bqForm.c, tempValue)
		K.Mod(K, L)
	}

	upperBound:=new(big.Int).Set(bqForm.a)
	upperBound.Sqrt( upperBound )
	upperBound.Mul(upperBound, Droot4th)

	var T *big.Int

	if L.Cmp(upperBound) < 0 {
		T = new(big.Int).Mul(N, K)
		a = new(big.Int).Mul(N, L)

		b = new(big.Int).Lsh(T, 1)
		b.Add(bqForm.b, b)

		c:= new(big.Int).Add( T,bqForm.b )
		c.Mul( c, K )
		c.Add( c, c1)
		c.Div( c, L)

		result:= &BQuadraticForm{
			a:            a,
			b:            b,
			c:            c,
			discriminant: bqForm.discriminant,
		}
		result.Reduction()
		return result
	}

	R2 := new(big.Int).Set(L)
	R1 := new(big.Int).Set(K)
	C2 := big.NewInt(0)
	C1 := big.NewInt(-1)

	R2, R1, C2, C1 = partialGCD(R2, R1, C2, C1, upperBound)

	T = new(big.Int).Mul(N, K)

	tempValue := new(big.Int).Mul(T, C1)
	M1 := new(big.Int).Mul(N, R1)
	M1.Add(M1, tempValue)
	M1.Div(M1, L)

	tempValue = new(big.Int).Add(bqForm.b, T)
	tempValue.Mul(R1, tempValue)

	M2 := new(big.Int).Mul(bqForm.c, S)
	M2.Mul(M2, C1)
	M2.Sub(tempValue, M2)
	M2.Div(M2, L)

	a = new(big.Int).Mul(R1, M1)
	tempValue = new(big.Int).Mul(C1, M2)
	a.Sub(a, tempValue)

	if C1.Sign() > 0 {
		a.Neg(a)
	}

	b = new(big.Int).Mul(a, C2)
	tempValue = new(big.Int).Mul(N, R1)
	b.Sub(tempValue, b)
	b.Lsh(b, 1)
	b.Div(b, C1)
	b.Sub(b, bqForm.b)
	b.Mod(b, new(big.Int).Lsh(a, 1))

	if a.Sign() < 0 {
		a.Neg(a)
	}

	result, _ := NewBQuadraticFormByDiscriminant(a, b, bqForm.discriminant)
	result.Reduction()
	return result
}

// The algortihm can be found in the page 39, Algorithm 3.6, Improved Arithmetic
// in the Ideal Class Group of Imaginary, Maxwell Sayles. NOTE: The implementment of this function
// may be a little different from Algorithm 3.6.
func expansion23StrictChains(input *big.Int, numberNode int) []*expansion23 {

	result := make([]*expansion23, 0)
	inputCopy := new(big.Int).Set(input)
	a, b := 0, 0

	for inputCopy.Sign() != 0 {

		minTree := make([]*expansion23, 0)
		minTree, inputCopy = generatePartialTree(inputCopy, numberNode, a, b)

		result = append(result, minTree...)
		indexLast := len(result) - 1
		a = result[indexLast].exponent2
		b = result[indexLast].exponent3
	}
	return result
}

// Starting from startVale, we will get two nodes. The total number of nodes will be bounded by numberNode.
// If the number of nodes equals numberNode, then the output is the minimal value of all branches.
func generatePartialTree(startValue *big.Int, numberNode, exponent2, exponent3 int) ([]*expansion23, *big.Int) {

	maxDeep := numberNode / 2
	nTimes := 0
	tempStartValueCopy := make([]*big.Int, 1)
	tempStartValueCopy[0] = startValue

	tempContainerCopy := make([][]*expansion23, 0)

	expon21, expon31 := exponent2, exponent3
	expon22, expon32 := exponent2, exponent3
	for nTimes < maxDeep {

		tempContainer := make([][]*expansion23, 0)
		tempStartValue := make([]*big.Int, 0)

		for i := 0; i < len(tempStartValueCopy); i++ {
			originalSlice1 := make([]*expansion23, 0)
			originalSlice2 := make([]*expansion23, 0)

			if nTimes > 0 {
				originalSlice1 = make([]*expansion23, len(tempContainerCopy[i]))
				originalSlice2 = make([]*expansion23, len(tempContainerCopy[i]))
				copy(originalSlice1, tempContainerCopy[i])
				copy(originalSlice2, tempContainerCopy[i])

				indexLast1 := len(originalSlice1) - 1
				expon21, expon31 = originalSlice1[indexLast1].exponent2, originalSlice1[indexLast1].exponent3

				indexLast2 := len(originalSlice2) - 1
				expon22, expon32 = originalSlice2[indexLast2].exponent2, originalSlice2[indexLast2].exponent3
			}

			temp1, tempValue1 := removedivisorof23(tempStartValueCopy[i], originalSlice1, 1, expon21, expon31)
			temp2, tempValue2 := removedivisorof23(tempStartValueCopy[i], originalSlice2, -1, expon22, expon32)

			tempStartValue = append(tempStartValue, tempValue1)
			tempStartValue = append(tempStartValue, tempValue2)

			originalSlice1 = append(originalSlice1, temp1...)
			originalSlice2 = append(originalSlice2, temp2...)

			tempContainer = append(tempContainer, originalSlice1)
			tempContainer = append(tempContainer, originalSlice2)

			if tempValue2.Sign() == 0 {
				return originalSlice2, tempValue2
			}
			if tempValue1.Sign() == 0 {
				return originalSlice1, tempValue1
			}

		}

		tempContainerCopy = copyDoubleSlice(tempContainer)
		tempStartValueCopy = make([]*big.Int, len(tempStartValue))
		copy(tempStartValueCopy, tempStartValue)
		nTimes++
	}

	result, value := pickMinusValueBranch(tempContainerCopy, tempStartValueCopy)
	return result, value
}

// Copy a double slice.
func copyDoubleSlice(input [][]*expansion23) [][]*expansion23 {

	length := len(input)
	inputCopy := make([][]*expansion23, length)

	for i := 0; i < length; i++ {

		temp := make([]*expansion23, len(input[i]))

		copy(temp, input[i])
		inputCopy[i] = temp
	}
	return inputCopy
}

// Get the slice of expansion23 according to the index of the minimal value of valueContainer.
func pickMinusValueBranch(inputSliceContainer [][]*expansion23, valueContainer []*big.Int) ([]*expansion23, *big.Int) {

	minIndex := 0
	tempMinValue := valueContainer[0]

	for i := 1; i < len(valueContainer); i++ {

		if valueContainer[i].Cmp(tempMinValue) < 0 {
			tempMinValue = valueContainer[i]
			minIndex = i
		}
	}
	return inputSliceContainer[minIndex], tempMinValue
}

// Given an Number N = 2^exponent2 * 3^exponent3 * (others). This function will give exponent2 and exponent3
// and others.
func removedivisorof23(inputValue *big.Int, inputExpansion23 []*expansion23, minusValue, expo2, expo3 int) ([]*expansion23, *big.Int) {

	result := make([]*expansion23, 0)
	a, b := expo2, expo3
	inputCopy := new(big.Int).Set(inputValue)

	if inputValue.Cmp(bigOne) == 0 {
		tempResult := Newexpansion23(a, b, 1)
		inputCopy := big.NewInt(0)
		result = append(result, tempResult)
		return result, inputCopy
	}

	for inputCopy.Bit(0) == 0 {
		inputCopy.Rsh(inputCopy, 1)
		a++
	}

	tempValue := new(big.Int).Mod(inputCopy, bigThree)
	for tempValue.Sign() == 0 {
		inputCopy.Div(inputCopy, bigThree)
		b++
		tempValue.Mod(inputCopy, bigThree)
	}

	tempResult := Newexpansion23(a, b, minusValue)

	if minusValue == 1 {
		inputCopy.Sub(inputCopy, bigOne)
	} else {
		inputCopy.Add(inputCopy, bigOne)
	}

	result = append(result, tempResult)
	return result, inputCopy
}

// We assume that bqForm is reduced. Then if bqForm is ambiguous iff b = 0 or a = b.
func (bqForm *BQuadraticForm) isAmbiguousQForm() bool {

	if bqForm.b.Sign() == 0 || bqForm.a.Cmp(bqForm.b) == 0 {
		return true
	}
	return false
}

// ref: Chapter 5, Improved Arithmetic in the Ideal Class Group of Imaginary
// Quadratic Number Fields, Maxwell Sayles.
// Code: https://github.com/maxwellsayles/liboptarith/blob/master/mpz_xgcd.c
func partialGCD(R2, R1, C2, C1, bound *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {

	A2, A1, B2, B1 := int64(0), int64(0), int64(0), int64(0)
	T, T1, rr2, rr1 := int64(0), int64(0), int64(0), int64(0)
	qq, bb := int64(0), int64(0)
	i := 0
	q, r, t1, t2 := big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)

	for R1.Sign() != 0 && R1.Cmp(bound) > 0 {

		T = int64(R2.BitLen() - (GMP_LIMB_BITS) + 1)
		T1 = int64(R1.BitLen() - (GMP_LIMB_BITS) + 1)

		if T < T1 {
			T = T1
		}
		if T < 0 {
			T = 0
		}

		r = new(big.Int).Rsh(R2, uint(T))
		rr2 = r.Int64()

		r = new(big.Int).Rsh(R1, uint(T))
		rr1 = r.Int64()

		r = new(big.Int).Rsh(bound, uint(T))
		bb = r.Int64()

		A2 = 0
		A1 = 1
		B2 = 1
		B1 = 0
		i = 0

		for rr1 != 0 && rr1 > bb {

			qq = rr2 / rr1

			T = rr2 - qq*rr1
			rr2 = rr1
			rr1 = T

			T = A2 - qq*A1
			A2 = A1
			A1 = T

			T = B2 - qq*B1
			B2 = B1
			B1 = T

			if (i & 1) > 0 {
				if (rr1 < -B1) || (rr2-rr1 < A1-A2) {
					break
				}
			} else {
				if (rr1 < -A1) || (rr2-rr1 < B1-B2) {
					break
				}
			}
			i++
		}

		if i == 0 {
			q, r = new(big.Int).DivMod(R2, R1, r)

			R2 = new(big.Int).Set(R1)
			R1 = r

			tempValue := new(big.Int).Set(C1)
			r = new(big.Int).Mul(q, C1)

			C1.Sub(C2, r)
			C2 = tempValue
		} else {
			t1.Mul(R2, new(big.Int).SetInt64(B2))
			t2.Mul(R1, new(big.Int).SetInt64(A2))
			r.Add(t1, t2)

			t1.Mul(R2, new(big.Int).SetInt64(B1))
			t2.Mul(R1, new(big.Int).SetInt64(A1))
			R1.Add(t1, t2)

			R2 = new(big.Int).Set(r)

			t1.Mul(C2, new(big.Int).SetInt64(B2))
			t2.Mul(C1, new(big.Int).SetInt64(A2))
			r.Add(t1, t2)

			t1.Mul(C2, new(big.Int).SetInt64(B1))
			t2.Mul(C1, new(big.Int).SetInt64(A1))
			C1.Add(t1, t2)

			C2 = new(big.Int).Set(r)

			if R1.Sign() < 0 {
				R1.Neg(R1)
				C1.Neg(C1)
			}

			if R2.Sign() < 0 {
				R2.Neg(R2)
				C2.Neg(C2)
			}

		}
	}

	if R2.Sign() < 0 {
		R2.Neg(R2)
		C2.Neg(C2)
		C1.Neg(C1)
	}

	return R2, R1, C2, C1
}
