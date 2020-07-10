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
	"math"
	"math/big"

	"github.com/getamis/alice/crypto/utils"
)

var (
	big0 = big.NewInt(0)
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

// RemoveZeros removes the zeros from the end of the polyminal.
func (p *Polynomial) RemoveZeros() *Polynomial {
	endIndex := 0
	for i := p.Len() - 1; i >= 0; i-- {
		if p.coefficients[i] != nil {
			endIndex = i
			break
		}
	}
	for i := endIndex; i >= 0; i-- {
		if p.coefficients[i].Cmp(big.NewInt(0)) != 0 {
			endIndex = i
			break
		}
	}
	newSlice := p.coefficients[:endIndex+1]
	return &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newSlice,
	}
}

// Mod makes sure all the coefficients of a polynominal is within zero to (field order-1).
func (p *Polynomial) Mod() *Polynomial {
	for i := 0; i < p.Len(); i++ {
		p.coefficients[i] = new(big.Int).Mod(p.coefficients[i], p.fieldOrder)
	}
	return p
}

// Add adds 2 polynomianls together.
func (p *Polynomial) Add(P *Polynomial) *Polynomial {
	// compare the length of 2 poly, and get the longer legnth number
	length := int(math.Max(float64(p.Len()), float64(P.Len())))
	newP := make([]*big.Int, length)
	for i := 0; i < length; i++ {
		newP[i] = new(big.Int).Add(p.coefficients[i], P.coefficients[i])
	}
	sum := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newP,
	}
	sum = sum.Mod()
	sum = sum.RemoveZeros()
	return sum
}

// Minus returns the difference between 2 polynominal (p-P)
func (p *Polynomial) Minus(P *Polynomial) *Polynomial {
	// compare the length of 2 poly, and get the longer legnth number
	length := int(math.Max(float64(p.Len()), float64(P.Len())))
	newPCoeff := make([]*big.Int, length)
	if p.Len() > P.Len() {
		for i := 0; i < length; i++ {
			if i < P.Len() {
				newPCoeff[i] = new(big.Int).Sub(p.coefficients[i], P.coefficients[i])
			} else {
				newPCoeff[i] = p.coefficients[i]
			}
		}
	} else if p.Len() < P.Len() {
		for i := 0; i < length; i++ {
			if i < p.Len() {
				newPCoeff[i] = new(big.Int).Sub(p.coefficients[i], P.coefficients[i])
			} else {
				newPCoeff[i] = new(big.Int).Sub(big.NewInt(0), P.coefficients[i])
			}
		}
	} else { // length equal
		for i := 0; i < length; i++ {
			newPCoeff[i] = new(big.Int).Sub(p.coefficients[i], P.coefficients[i])
		}
	}
	newP := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newPCoeff,
	}
	newP = newP.Mod()
	newP = newP.RemoveZeros()
	return newP
}

// Mul multiply 2 polynominals into 1 then output
func (p *Polynomial) Mul(p2 *Polynomial) *Polynomial {
	p = p.RemoveZeros()
	p2 = p2.RemoveZeros()
	length := p.Len() + p2.Len() - 1
	newP := make([]*big.Int, length)
	product := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newP,
	}
	for i := 0; i < length; i++ {
		product.coefficients[i] = big.NewInt(0)
	}
	for i := 0; i < p.Len(); i++ {
		for j := 0; j < p2.Len(); j++ {
			newP[i+j] = new(big.Int).Add(newP[i+j], new(big.Int).Mul(p.coefficients[i], p2.coefficients[j]))
		}
	}
	product = product.Mod()
	product = product.RemoveZeros()
	return product
}

// rem only persves terms with lower degree and keep the rest of the coefiicients within fieldorder // also reduces its cap
func (p *Polynomial) rem(l int) *Polynomial {
	newPCoeff := make([]*big.Int, l, l)
	for i := 0; i < l; i++ {
		newPCoeff[i] = p.coefficients[i]
	}
	remainder := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newPCoeff,
	}
	remainder = remainder.Mod()
	remainder = remainder.RemoveZeros()
	return remainder
}

// algorithm 9.3
// invert computes the inversion of an polynomial using Newton iteration
// l is the degree of the "moded" term. example: l = 4 if we are moding x^4
func (p *Polynomial) invert(l *big.Int) *Polynomial {
	r := math.Ceil(math.Log2(float64(l.Int64())))
	g0Coeff := make([]*big.Int, l.Int64()+2)
	g0 := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: g0Coeff,
	}
	g0.SetConstant(big.NewInt(1))

	giCoeff := make([]*big.Int, l.Int64()+2)
	gi := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: giCoeff,
	}

	Just2Coeff := make([]*big.Int, l.Int64()+2)
	Just2 := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: Just2Coeff,
	}
	Just2.SetConstant(big.NewInt(2))
	Just2 = Just2.RemoveZeros()
	gi = (Just2.Minus(p)).rem(2)   // initial gi which is g1
	for i := 1; i <= int(r); i++ { // g0 is g_{i-1} in algorithm 9.3
		gTemp := gi
		gi = (Just2.Mul(g0).Minus(p.Mul(g0.Mul(g0)))).rem(int(math.Pow(2, float64(i))))
		gi = gi.Mod()
		gi = gi.RemoveZeros()
		g0 = gTemp
	}
	return gi
}

// rev computes the reversal of a as rev_{k}(a) = x^{k}*a(1/x), where a is a polynomial.
func (p *Polynomial) rev(k uint32) *Polynomial {
	if k < p.Degree() {
		// will produce polynomial with negative degree terms
		return nil
	}
	newPCoeff := make([]*big.Int, p.Len())
	for currentIndex := 0; currentIndex < p.Len(); currentIndex++ {
		newIndex := currentIndex*(-1) + int(k)
		newPCoeff[newIndex] = p.coefficients[currentIndex]
	}
	rev := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newPCoeff,
	}
	rev = rev.Mod()
	rev = rev.RemoveZeros()
	return rev
}

// CheckIfOnlyZero checks if the polynomial has nothing but zero
func (p *Polynomial) CheckIfOnlyZero() bool {
	allZero := true
	for i := p.Len() - 1; i >= 0; i-- {
		if p.coefficients[i].Cmp(big.NewInt(0)) != 0 {
			allZero = false
			break
		}
	}
	return allZero
}

// FDiv (algorithm 9.5) means fast division with remainder, it performs division between polynomials with smaller complexity than the normal one
func (p *Polynomial) FDiv(b *Polynomial) (q, r *Polynomial, err error) {
	b = b.RemoveZeros()
	err = utils.ErrDivisionByZero
	if b.CheckIfOnlyZero() {
		return nil, nil, err
	}
	length := p.Len()
	newPCoeff := make([]*big.Int, length)
	if p.Degree() < b.Degree() {
		newP := &Polynomial{
			fieldOrder:   p.fieldOrder,
			coefficients: newPCoeff,
		}
		newP.SetConstant(big.NewInt(0))
		newP = newP.RemoveZeros()
		newP = newP.Mod()
		return newP, p, nil
	}
	for i := 0; i < length; i++ {
		newPCoeff[i] = big.NewInt(0)
	}
	m := p.Degree() - b.Degree()
	// call invert() (algorithm 9.3) to compute the inverse of rev deg b (b) belongs to D[x] mod x^{m+1}
	l := big.NewInt(int64(m) + 1)
	RevB := b.rev(b.Degree())
	invRevB := RevB.invert(l)
	qAsterisk := p.rev(p.Degree()).Mul(invRevB).rem(int(m) + 1)
	q = qAsterisk.rev(m)
	r = p.Minus(b.Mul(q))
	return q, r, nil
}
