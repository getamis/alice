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

package polynomial

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/utils"
)

var (
	// ErrEmptyCoefficients is returned if the coefficients is empty
	ErrEmptyCoefficients = errors.New("empty coefficient")
)

// Polynomial represents a polynomial of arbitrary degree
type Polynomial struct {
	fieldOrder   *big.Int
	coefficients []*big.Int
}

// NewPolynomial news a polynomial module fieldOrder.
// Warning: This function may produce modulo bias if applied directly to slices that have not previously undergone rejection sampling.
func NewPolynomial(fieldOrder *big.Int, coefficients []*big.Int) (*Polynomial, error) {
	if err := utils.EnsureFieldOrder(fieldOrder); err != nil {
		return nil, err
	}
	if len(coefficients) == 0 {
		return nil, ErrEmptyCoefficients
	}
	mc := make([]*big.Int, len(coefficients))
	for i, c := range coefficients {
		mc[i] = new(big.Int).Mod(c, fieldOrder)
	}
	return &Polynomial{
		fieldOrder:   fieldOrder,
		coefficients: mc,
	}, nil
}

// RandomPolynomial randoms a polynomial with random coefficient
func RandomPolynomial(fieldOrder *big.Int, degree uint32) (*Polynomial, error) {
	coefficients := make([]*big.Int, degree+1)
	for i := 0; i < len(coefficients); i++ {
		tempValue, err := utils.RandomInt(fieldOrder)
		if err != nil {
			return nil, err
		}
		coefficients[i] = tempValue
	}
	return NewPolynomial(fieldOrder, coefficients)
}

// Differentiate returns a differentiated function
// Given f(x) is a polynomial, then output is f^(diffTime)(x) mod field order
// Ex: f(x)=x^5+2*x^3, diffTime = 1 Then f^(1)(x)= 5*x^4+6*x^2 = 2*x^4.
func (p *Polynomial) Differentiate(diffTime uint32) *Polynomial {
	lengthPolyACoeff := uint32(p.Len())
	reduceDegree := lengthPolyACoeff - diffTime
	diffCoeffSlice := make([]*big.Int, reduceDegree)
	for i := diffTime; i < lengthPolyACoeff; i++ {
		tempValue := uint64(1)
		for j := uint32(0); j < diffTime; j++ {
			tempValue *= uint64(i - j)
		}
		exTra := new(big.Int).SetUint64(tempValue)
		tempCoeff := new(big.Int).Mul(p.coefficients[i], exTra)
		tempCoeff = new(big.Int).Mod(tempCoeff, p.fieldOrder)
		diffCoeffSlice[i-diffTime] = tempCoeff
	}
	if diffTime >= lengthPolyACoeff {
		return &Polynomial{
			fieldOrder:   p.fieldOrder,
			coefficients: []*big.Int{big.NewInt(0)},
		}
	}
	return &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: diffCoeffSlice,
	}
}

// Evaluate returns f(x) mod field order
// Given a polynomial f(x), then the output is f(x)
// Ex:f(3)=x^5+2*x^3, x=1, fieldOrder=3 Then f(1)=3=0 mod field order
func (p *Polynomial) Evaluate(x *big.Int) *big.Int {
	if x.Sign() == 0 {
		return p.coefficients[0]
	}
	// Compute the polynomial value using Horner's method.
	result := new(big.Int).Set(p.coefficients[len(p.coefficients)-1])
	for i := len(p.coefficients) - 2; i >= 0; i-- {
		result = new(big.Int).Mul(result, x)
		result = new(big.Int).Add(result, p.coefficients[i])
		result = new(big.Int).Mod(result, p.fieldOrder)
	}
	return result
}

// Get gets the ith coefficients. If i is out of range, return nil.
func (p *Polynomial) Get(i int) *big.Int {
	if i < 0 || i >= len(p.coefficients) {
		return nil
	}
	return new(big.Int).Set(p.coefficients[i])
}

// Len returns the length of coefficients
func (p *Polynomial) Len() int {
	return len(p.coefficients)
}

// Degree returns the degree of the polynomial
func (p *Polynomial) Degree() uint32 {
	return uint32(p.Len() - 1)
}

// SetConstant sets the constant term of the polynomial
func (p *Polynomial) SetConstant(value *big.Int) {
	p.coefficients[0] = value
}

// Max compares 2 integers and return the larger one
func Max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

// need a function to delete the zeros at the end of the slice

// Add adds 2 polynomianls together.
func (p *Polynomial) Add(P *Polynomial) *Polynomial {
	// compare the length of 2 poly, and get the longer legnth number
	var length = Max(p.Len(), P.Len())
	// initialize a new slice for their addition with a size of the longer length
	var newP = make([]*big.Int, length)
	// loop through longer length to perform addtion on each term
	for i := 0; i < length; i++ {
		newP[i] = new(big.Int).Add(p.coefficients[i], P.coefficients[i])
	}
	// mod slice of coefficient with fieldOrder
	for i := 0; i < length; i++ {
		newP[i] = new(big.Int).Mod(newP[i], p.fieldOrder)
	}
	// output
	return &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newP,
	}
}

// Minus returns the difference between 2 polynominal (p-P)
func (p *Polynomial) Minus(P *Polynomial) *Polynomial {
	// compare the length of 2 poly, and get the longer legnth number
	var length = Max(p.Len(), P.Len())
	// initialize a new slice for their addition with a size of the longer length
	var newP = make([]*big.Int, length)
	// loop through longer length to perform subtraction on each term
	for i := 0; i < length; i++ {
		newP[i] = new(big.Int).Sub(p.coefficients[i], P.coefficients[i])
	}
	// mod slice of coefficient with fieldOrder
	for i := 0; i < length; i++ {
		newP[i] = new(big.Int).Mod(newP[i], p.fieldOrder)
	}
	// output
	return &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newP,
	}
}

// Mul multiply 2 polynominals into 1 then output
func (p *Polynomial) Mul(P *Polynomial) *Polynomial {
	// new length will be Len(p)+Len(P)-1
	var length = p.Len() + P.Len() - 1
	// initialize a new slice for their product with a size of length
	var newP = make([]*big.Int, length)
	product := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newP,
	}
	// And set all coeffcients to zero
	for i := 0; i < length; i++ {
		product.coefficients[i] = big.NewInt(0)
	}
	// loop through the length to perform multiplication on each term
	for i := 0; i < p.Len(); i++ {
		for j := 0; j < P.Len(); j++ {
			newP[i+j] = new(big.Int).Add(newP[i+j], new(big.Int).Mul(p.coefficients[i], P.coefficients[i]))
		}
	}
	// mod slice of coefficient with fieldOrder
	for i := 0; i < length; i++ {
		newP[i] = new(big.Int).Mod(newP[i], p.fieldOrder)
	}
	// output
	return product
}

// from https://rosettacode.org/wiki/Polynomial_long_division#Go
// N: dividend
// D: divisor
// Q: quotient
// R: remainder
// degree ignores the zeros and gets the actul degree of a polynominal.
func degree(p *Polynomial) int {
	for d := p.Len() - 1; d >= 0; d-- {
		if p.Get(d) != big.NewInt(0) {
			return d
		}
	}
	return -1
}

// Degree ignores the zeros and gets the actul degree of a []*big.Int.
func Degree(coeff []*big.Int) int {
	for d := len(coeff) - 1; d >= 0; d-- {
		if coeff[d] != big.NewInt(0) {
			return d
		}
	}
	return -1
}

// Div divides 1 polynominal by another polynominal then returns quotient and remiander polymonial.
func Div(nn, dd *Polynomial) (q, r *Polynomial) {
	// error for negative degree
	if degree(dd) < 0 || degree(nn) < degree(dd) {
		fmt.Print("Error")
		return
	}
	r = nn
	// initiate new slice for quotient's coeffcient
	var qCoeff = make([]*big.Int, degree(nn)-degree(dd)+1)
	// initiate new slice for dividend's coeffcient
	var nCoeff = make([]*big.Int, degree(nn)-degree(dd)+1)
	// then copy everything over
	copy(nCoeff[:], nn.coefficients)
	if degree(nn) >= degree(dd) {
		// loop till degree of divisor(dd) is larger
		for degree(nn) >= degree(dd) {
			// new slice to store shifted divisor
			dCoeff /*originally d*/ := make([]*big.Int, degree(nn)+1)
			// dCoeff = D shifted right by (degree(N) - degree(D)), so that N and D are in the same degree
			copy(dCoeff[degree(nn)-degree(dd):], dd.coefficients)
			// q(degree(N) - degree(D)) = N(degree(N)) / d(degree(d))
			q.coefficients[degree(nn)-degree(dd)] = new(big.Int).Div(nn.Get(degree(nn)), dCoeff[Degree(dCoeff)])
			for i := range dCoeff {
				dCoeff[i] = new(big.Int).Mul(dCoeff[i], q.Get(degree(nn)-degree(dd)))
				nCoeff[i] = new(big.Int).Sub(nn.Get(i), dCoeff[i])
			}
		}

	}
	// return q, nn
	return &Polynomial{ // FIXME put this together within the same scope of its declaration
			fieldOrder:   q.fieldOrder,
			coefficients: qCoeff,
		}, &Polynomial{
			fieldOrder:   nn.fieldOrder,
			coefficients: nCoeff,
		}
}
