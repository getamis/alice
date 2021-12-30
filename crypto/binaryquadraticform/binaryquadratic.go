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

package binaryquadraticform

import (
	"errors"
	"math/big"
	"reflect"

	dbns "github.com/aisuosuo/alice/crypto/dbnssystem"
)

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)

	gmbLimbBits = 64

	// Recommend 4.
	deepTree = 7

	// ErrPositiveDiscriminant is returned if the discriminant is negative.
	ErrPositiveDiscriminant = errors.New("not a negative discriminant")
	// ErrDifferentDiscriminant is returned if the discriminants are different.
	ErrDifferentDiscriminant = errors.New("different discriminant")
	// ErrEmptySlice is returned if the slice is empty.
	ErrEmptySlice = errors.New("slice is empty")
	// ErrZero is returned if the integer is zero.
	ErrZero = errors.New("the integer is zero")
)

// In this library, we only consider positive definite quadratic forms
/* This Library only supports some operations of "primitives positive definite binary quadratic forms" (i.e.
 * corresponding to ideal operations over imaginary quadratic fields).
 * A Quadratic form is given by: (a,b,c) := ax^2+bxy+cy^2 with discriminant = b^2 - 4ac < 0
 */
type BQuadraticForm struct {
	a *big.Int
	b *big.Int
	c *big.Int

	// cache
	shanksBound  *big.Int
	discriminant *big.Int
}

// Give a, b, c to construct quadratic forms.
func NewBQuadraticForm(a *big.Int, b *big.Int, c *big.Int) (*BQuadraticForm, error) {
	discriminant, err := computeDiscriminant(a, b, c)
	if err != nil {
		return nil, err
	}
	// The definition of shranksBound is the floor of (|discriminant/4|)^(1/4).
	shranksBound := computeroot4thOver4(discriminant)
	bqform := &BQuadraticForm{
		a:            a,
		b:            b,
		c:            c,
		shanksBound:  shranksBound,
		discriminant: discriminant,
	}
	bqform.reduction()
	return bqform, nil
}

func computeDiscriminant(a *big.Int, b *big.Int, c *big.Int) (*big.Int, error) {
	// discriminant = b^2 - 4ac
	discriminant := new(big.Int).Mul(b, b)
	ac := new(big.Int).Mul(a, c)
	discriminant = discriminant.Sub(discriminant, ac.Lsh(ac, 2))
	if discriminant.Sign() > -1 {
		return nil, ErrPositiveDiscriminant
	}
	return discriminant, nil
}

// Give a, b, discriminant to construct quadratic forms.
func NewBQuadraticFormByDiscriminant(a *big.Int, b *big.Int, discriminant *big.Int) (*BQuadraticForm, error) {
	if discriminant.Sign() > -1 {
		return nil, ErrPositiveDiscriminant
	}

	// The definition of shranksBound is the floor of (|discriminant/4|)^(1/4).
	shranksBound := computeroot4thOver4(discriminant)
	return newBQForm(a, b, discriminant, shranksBound)
}

func newBQForm(a *big.Int, b *big.Int, discriminant *big.Int, shranksBound *big.Int) (*BQuadraticForm, error) {
	bSquare := new(big.Int).Mul(b, b)
	c := new(big.Int).Sub(bSquare, discriminant)
	c.Div(c, a)
	c.Rsh(c, 2)
	bqform := &BQuadraticForm{
		a:            a,
		b:            b,
		c:            c,
		shanksBound:  shranksBound,
		discriminant: new(big.Int).Set(discriminant),
	}
	bqform.reduction()
	return bqform, nil
}

// Reduction of Positive Difinite Forms: Given a positive definite quadratic form f = (a,b,c)
// of discriminant D = b^2 -4ac < 0, this algorithm ouputs the unique reduced form equivalent
// to f. cf: Algorithm 5.4.2, A Course in Computational Algebraic Number theory, Cohen GTM 138.
func (bqForm *BQuadraticForm) reduction() {
	CopyNega := new(big.Int).Neg(bqForm.a)
	// if -a < b <= a
	if bqForm.b.Cmp(CopyNega) == 1 && bqForm.b.Cmp(bqForm.a) <= 0 {
		bqForm.reductionMainStep()
		return
	}
	bqForm.euclideanStep()
	bqForm.reductionMainStep()
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
	if bqForm.a.Cmp(absoluteB) == 0 && bqForm.b.Cmp(big0) > -1 {
		return true
	}
	// a = c and b >= 0
	if bqForm.a.Cmp(bqForm.c) == 0 && bqForm.b.Cmp(big0) > -1 {
		return true
	}
	return false
}

// Get the coefficient of a binary quadratic form: ax^2 + bxy + cy^2
// Get a
func (bqForm *BQuadraticForm) GetA() *big.Int {
	return bqForm.a
}

// Get b
func (bqForm *BQuadraticForm) GetB() *big.Int {
	return bqForm.b
}

// Get c
func (bqForm *BQuadraticForm) GetC() *big.Int {
	return bqForm.c
}

// Get discriminant
func (bqForm *BQuadraticForm) GetDiscriminant() *big.Int {
	return bqForm.discriminant
}

func (bqForm *BQuadraticForm) Equal(bqForm1 *BQuadraticForm) bool {
	return reflect.DeepEqual(bqForm, bqForm1)
}

// The inverse quadratic Form of [a,b,c] is [a,-b,c]
func (bqForm *BQuadraticForm) Inverse() *BQuadraticForm {
	result := &BQuadraticForm{
		a:            new(big.Int).Set(bqForm.a),
		b:            new(big.Int).Neg(bqForm.b),
		c:            new(big.Int).Set(bqForm.c),
		shanksBound:  new(big.Int).Set(bqForm.shanksBound),
		discriminant: new(big.Int).Set(bqForm.discriminant),
	}
	result.reduction()
	return result
}

// Identity element := bqForm * bqForm.Inverse()
func (bqForm *BQuadraticForm) Identity() *BQuadraticForm {
	bqFormInverse := bqForm.Copy()
	bqFormInverse = bqFormInverse.Inverse()
	// Ignore error here
	result, _ := bqForm.Composition(bqFormInverse)
	return result
}

/* The composition operation of binary quadratic forms
 * NUCOMP algorithm. Adapted from "Solving the Pell Equation"
 * by Michael J. Jacobson, Jr. and Hugh C. Williams.
 * http://www.springer.com/mathematics/numbers/book/978-0-387-84922-5
 * The code original author: Maxwell Sayles.
 * Code: https://github.com/maxwellsayles/libqform/blob/master/mpz_qform.c
 */
func (bqForm *BQuadraticForm) Composition(inputForm *BQuadraticForm) (*BQuadraticForm, error) {
	if bqForm.discriminant.Cmp(inputForm.discriminant) != 0 {
		return nil, ErrDifferentDiscriminant
	}
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
	if SP.Cmp(big1) != 0 {
		u2, v2, S = exGCD(SP, ss)
		K.Mul(K, u2)
		tempValue := new(big.Int).Mul(v2, c2)
		K.Sub(K, tempValue)
		if S.Cmp(big1) != 0 {
			a1.Div(a1, S)
			a2.Div(a2, S)
			c2.Mul(c2, S)
		}
		K.Mod(K, a1)
	}

	if a1.Cmp(bqForm.shanksBound) < 0 {
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
			shanksBound:  new(big.Int).Set(bqForm.shanksBound),
			discriminant: new(big.Int).Set(bqForm.discriminant),
		}
		result.reduction()
		return result, nil
	}

	R2 := new(big.Int).Set(a1)
	R1 := new(big.Int).Set(K)
	C2 := big.NewInt(0)
	C1 := big.NewInt(-1)
	_, R1, C2, C1 = partialGCD(R2, R1, C2, C1, bqForm.shanksBound)
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
	return newBQForm(a, b, bqForm.discriminant, bqForm.shanksBound)
}

/* The output is bqForm ^ power. Ref: Algorithm 3.2, page 30,
 * Improved Arithmetic in the Ideal Class Group of Imaginary
 * Quadratic Number Fields, Maxwell Sayles.
 */
func (bqForm *BQuadraticForm) Exp(power *big.Int) (*BQuadraticForm, error) {
	R := bqForm.Identity()
	T := bqForm.Copy()
	if power.Cmp(big0) == 0 {
		return R, nil
	}
	dbnsMentor := dbns.NewDBNS(deepTree)
	expansion, err := dbnsMentor.ExpansionBase2And3(power)
	if err != nil {
		return nil, err
	}
	a, b, index := 0, 0, 0
	for index < len(expansion) {
		var err error
		exp2 := expansion[index].GetExp2()
		for a < exp2 {
			T, err = T.square()
			if err != nil {
				return nil, err
			}
			a++
		}
		exp3 := expansion[index].GetExp3()
		for b < exp3 {
			T, err = T.cube()
			if err != nil {
				return nil, err
			}
			b++
		}
		sign := expansion[index].GetSign()
		if sign == 1 {
			R, err = R.Composition(T)
		} else {
			R, err = R.Composition(T.Inverse())
		}
		if err != nil {
			return nil, err
		}
		R.reduction()
		index++
	}
	return R, nil
}

// copy the binary quadratic form
func (bqForm *BQuadraticForm) Copy() *BQuadraticForm {
	return &BQuadraticForm{
		a:            new(big.Int).Set(bqForm.a),
		b:            new(big.Int).Set(bqForm.b),
		c:            new(big.Int).Set(bqForm.c),
		shanksBound:  new(big.Int).Set(bqForm.shanksBound),
		discriminant: new(big.Int).Set(bqForm.discriminant),
	}
}

// Reduction of Positive definite forms.
func (bqForm *BQuadraticForm) reductionMainStep() {
	for !bqForm.IsReducedForm() {
		// if a > c, set b = -b and exchange a and c.
		if bqForm.a.Cmp(bqForm.c) > 0 {
			bqForm.b.Neg(bqForm.b)
			bqForm.a, bqForm.c = bqForm.c, bqForm.a

			// if a = c and b < 0, set b = -b
		} else if bqForm.a.Cmp(bqForm.c) == 0 && bqForm.b.Cmp(big0) < 0 {
			bqForm.b.Neg(bqForm.b)
		}
		bqForm.euclideanStep()
	}
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
		q.Add(q, big1)
	}

	// c = c - 1/2(b+r)q, b = r
	bPlusrQ := new(big.Int).Add(bqForm.b, r)
	bPlusrQ.Mul(bPlusrQ, q)
	halfbPlusrQ := new(big.Int).Rsh(bPlusrQ, 1)
	bqForm.c.Sub(bqForm.c, halfbPlusrQ)
	bqForm.b = r
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
 * The code original author : Maxwell Sayles.
 * Code: https://github.com/maxwellsayles/libqform/blob/master/mpz_qform.c
 */
func (bqForm *BQuadraticForm) square() (*BQuadraticForm, error) {
	var a, b *big.Int
	a1 := new(big.Int).Set(bqForm.a)
	b1 := new(big.Int).Set(bqForm.b)
	c1 := new(big.Int).Set(bqForm.c)
	_, v, s := exGCD(a1, b1)
	U := new(big.Int).Mul(v, bqForm.c)
	U.Neg(U)
	if s.Cmp(big1) != 0 {
		a1.Div(a1, s)
		c1.Mul(c1, s)
	}
	U.Mod(U, a1)
	if a1.Cmp(bqForm.shanksBound) < 1 {
		T := new(big.Int).Mul(a1, U)
		a = new(big.Int).Mul(a1, a1)
		b := new(big.Int).Lsh(T, 1)
		b.Add(b1, b)
		c := new(big.Int).Add(b1, T)
		c.Mul(c, U)
		c.Add(c, c1)
		c.Div(c, a1)
		result := &BQuadraticForm{
			a:            a,
			b:            b,
			c:            c,
			shanksBound:  new(big.Int).Set(bqForm.shanksBound),
			discriminant: new(big.Int).Set(bqForm.discriminant),
		}
		result.reduction()
		return result, nil
	}
	R2 := new(big.Int).Set(a1)
	R1 := new(big.Int).Set(U)
	C2 := big.NewInt(0)
	C1 := big.NewInt(-1)
	_, R1, C2, C1 = partialGCD(R2, R1, C2, C1, bqForm.shanksBound)
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
	return newBQForm(a, b, bqForm.discriminant, bqForm.shanksBound)
}

/*
 * Computes a reduced ideal equivalent to the cube of an ideal.
 * Adapted from "Fast Ideal Cubing in Imaginary Quadratic Number
 * and Function Fields" by Laurent Imbert, Michael J. Jacobson, Jr. and
 * Arthur Schmidt.
 * www.lirmm.fr/~imbert/pdfs/cubing_amc_2010.pdf
 * The code original author : Maxwell Sayles.
 * Code: https://github.com/maxwellsayles/libqform/blob/master/mpz_qform.c
 */
func (bqForm *BQuadraticForm) cube() (*BQuadraticForm, error) {
	aModb := new(big.Int).Mod(bqForm.b, bqForm.a)
	if aModb.Sign() == 0 {
		return bqForm, nil
	}
	var S, N, L, K, a, b *big.Int
	c1 := new(big.Int).Set(bqForm.c)
	_, v1, S1 := exGCD(bqForm.a, bqForm.b)
	if S1.Cmp(big1) != 0 {
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
		tempValue.Sub(tempValue, big2)
		tempValue.Mul(tempValue, v1)
		K = tempValue.Mul(bqForm.c, tempValue)
		K.Mod(K, L)
	}
	upperBound := new(big.Int).Set(bqForm.a)
	upperBound.Sqrt(upperBound)
	upperBound.Mul(upperBound, bqForm.shanksBound)
	var T *big.Int
	if L.Cmp(upperBound) < 0 {
		T = new(big.Int).Mul(N, K)
		a = new(big.Int).Mul(N, L)
		b = new(big.Int).Lsh(T, 1)
		b.Add(bqForm.b, b)
		c := new(big.Int).Add(T, bqForm.b)
		c.Mul(c, K)
		c.Add(c, c1)
		c.Div(c, L)
		result := &BQuadraticForm{
			a:            a,
			b:            b,
			c:            c,
			shanksBound:  new(big.Int).Set(bqForm.shanksBound),
			discriminant: new(big.Int).Set(bqForm.discriminant),
		}
		result.reduction()
		return result, nil
	}
	R2 := new(big.Int).Set(L)
	R1 := new(big.Int).Set(K)
	C2 := big.NewInt(0)
	C1 := big.NewInt(-1)
	_, R1, C2, C1 = partialGCD(R2, R1, C2, C1, upperBound)
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
	return newBQForm(a, b, bqForm.discriminant, bqForm.shanksBound)
}

// ref: Chapter 5, Improved Arithmetic in the Ideal Class Group of Imaginary
// Quadratic Number Fields, Maxwell Sayles.
// Code: https://github.com/maxwellsayles/liboptarith/blob/master/mpz_xgcd.c
func partialGCD(R2, R1, C2, C1, bound *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	var A2, A1, B2, B1, T, T1, rr2, rr1, qq, bb int64
	var q, r *big.Int

	for R1.Sign() != 0 && R1.Cmp(bound) > 0 {
		T = int64(R2.BitLen() - (gmbLimbBits) + 1)
		T1 = int64(R1.BitLen() - (gmbLimbBits) + 1)
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
		i := 0
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
			t1 := new(big.Int).Mul(R2, new(big.Int).SetInt64(B2))
			t2 := new(big.Int).Mul(R1, new(big.Int).SetInt64(A2))
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

// Compute (|value/4|)^(1/4). Note that: If the value is large enough, then this function always outputs the floor of (|value/4|)^(1/4).
func computeroot4thOver4(value *big.Int) *big.Int {
	absValue := new(big.Int).Abs(value)
	pqVer4 := new(big.Int).Rsh(absValue, 2)
	pqVer4 = new(big.Int).Sqrt(pqVer4)
	pqRoot4 := new(big.Int).Sqrt(pqVer4)
	return pqRoot4
}
