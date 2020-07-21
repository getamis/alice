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
	// ErrInvalidPolynomial is returned if the coefficient of the highest degree term is zero
	ErrInvalidPolynomial = errors.New("invalid polynomial")
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

// removeZeros removes the zeros from the end of the polyminal.
func (p *Polynomial) removeZeros() *Polynomial {
	for i := p.Len() - 1; i >= 0; i-- {
		if p.coefficients[i].Cmp(big0) == 0 {
			continue
		}
		newSlice := p.coefficients[:i+1]
		return &Polynomial{
			fieldOrder:   p.fieldOrder,
			coefficients: newSlice,
		}
	}
	//should return constant term, which is zero, when all the coeffcients are 0
	newSlice := p.coefficients[:1]
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

// checkIfValid checks if the polynomial has a non-zero coefficient for the highest degree term while constant term can be zero
func (p *Polynomial) checkIfValid() bool {
	if p.coefficients[p.Len()-1] == nil {
		return false
	}
	if p.coefficients[p.Len()-1].Cmp(big0) == 0 && p.Len() != 1 {
		return false
	}
	return true
}

// Add is driver of add
func (p *Polynomial) Add(P *Polynomial) (*Polynomial, error) {
	if p.checkIfValid() != true || P.checkIfValid() != true {
		return nil, ErrInvalidPolynomial
	}
	return p.add(P), nil
}

// add adds 2 polynomianls together.
func (p *Polynomial) add(P *Polynomial) *Polynomial {
	length := int(math.Max(float64(p.Len()), float64(P.Len())))
	newPCoeff := make([]*big.Int, length)
	for i := 0; i < length; i++ {
		newPCoeff[i] = big0
	}
	for i := 0; i < p.Len(); i++ {
		newPCoeff[i] = new(big.Int).Add(newPCoeff[i], p.coefficients[i])
	}
	for i := 0; i < P.Len(); i++ {
		newPCoeff[i] = new(big.Int).Add(newPCoeff[i], P.coefficients[i])
	}
	sum := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newPCoeff,
	}
	sum = sum.Mod()
	sum = sum.removeZeros()
	return sum
}

// Minus is driver of minus
func (p *Polynomial) Minus(P *Polynomial) (*Polynomial, error) {
	if p.checkIfValid() != true || P.checkIfValid() != true {
		return nil, ErrInvalidPolynomial
	}
	return p.minus(P), nil
}

// minus returns the difference between 2 polynominal (p-P)
func (p *Polynomial) minus(P *Polynomial) *Polynomial {
	// compare the length of 2 poly, and get the longer legnth number
	newPCoeff := make([]*big.Int, P.Len())
	for i := 0; i < P.Len(); i++ {
		newPCoeff[i] = new(big.Int).Neg(P.coefficients[i])
	}
	negP := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newPCoeff,
	}
	// negP = negP.RemoveZeros()
	newP := p.add(negP)
	newP = newP.Mod()
	newP = newP.removeZeros()
	return newP
}

// Mul is the driver of mul
func (p *Polynomial) Mul(p2 *Polynomial) (*Polynomial, error) {
	if p.checkIfValid() != true || p2.checkIfValid() != true {
		return nil, ErrInvalidPolynomial
	}
	return p.mul(p2), nil
}

// mul multiply 2 polynominals into 1 then output
func (p *Polynomial) mul(p2 *Polynomial) *Polynomial {
	p = p.removeZeros()
	p2 = p2.removeZeros()
	length := p.Len() + p2.Len() - 1
	newP := make([]*big.Int, length)
	product := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newP,
	}
	for i := 0; i < length; i++ {
		product.coefficients[i] = big0
	}
	for i := 0; i < p.Len(); i++ {
		for j := 0; j < p2.Len(); j++ {
			newP[i+j] = new(big.Int).Add(newP[i+j], new(big.Int).Mul(p.coefficients[i], p2.coefficients[j]))
		}
	}
	product = product.Mod()
	product = product.removeZeros()
	return product
}

// rem only persves terms with lower degree and keep the rest of the coefiicients within fieldorder // also reduces its cap
func (p *Polynomial) rem(l int) *Polynomial {
	newPCoeff := make([]*big.Int, l, l)
	for i := 0; i < l; i++ {
		newPCoeff[i] = new(big.Int).Set(p.coefficients[i])
	}
	remainder := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: newPCoeff,
	}
	remainder = remainder.Mod()
	remainder = remainder.removeZeros()
	return remainder
}

// algorithm 9.3
// invert computes the inversion of an polynomial using Newton iteration
// l is the degree of the "moded" term. example: l = 4 if we are moding x^4
func (p *Polynomial) invert(l *big.Int) *Polynomial {
	r := math.Ceil(math.Log2(float64(l.Int64())))
	g0Coeff := make([]*big.Int, 1)
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

	Just2Coeff := make([]*big.Int, 1)
	Just2 := &Polynomial{
		fieldOrder:   p.fieldOrder,
		coefficients: Just2Coeff,
	}
	Just2.SetConstant(big.NewInt(2))
	// Just2 = Just2.RemoveZeros()
	gi = (Just2.minus(p)).rem(2)   // initial gi which is g1
	for i := 1; i <= int(r); i++ { // g0 is g_{i-1} in algorithm 9.3
		gTemp := gi
		pgg := p.mul(g0.mul(g0))
		Jm := Just2.mul(g0)
		Jmm := Jm.minus(pgg)
		gi = (Jmm).rem(int(math.Pow(2, float64(i))))
		gi = gi.Mod()
		gi = gi.removeZeros()
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
	rev = rev.removeZeros()
	return rev
}

// CheckIfOnlyZero checks if the polynomial has nothing but zero
func (p *Polynomial) CheckIfOnlyZero() bool {
	for i := p.Len() - 1; i >= 0; i-- {
		if p.coefficients[i].Cmp(big.NewInt(0)) != 0 {
			return false
		}
	}
	return true
}

// FDiv is the driver of fDiv
func (p *Polynomial) FDiv(b *Polynomial) (q, r *Polynomial, err error) {
	if p.checkIfValid() != true || b.checkIfValid() != true {
		return nil, nil, ErrInvalidPolynomial
	}
	if b.CheckIfOnlyZero() {
		return nil, nil, utils.ErrDivisionByZero
	}
	q, r = p.fDiv(b)
	return q, r, nil
}

// FDiv (algorithm 9.5) means fast division with remainder, it performs division between polynomials with smaller complexity than the normal one
func (p *Polynomial) fDiv(b *Polynomial) (q, r *Polynomial) {
	b = b.removeZeros()
	newPCoeff := make([]*big.Int, 1)
	if p.Degree() < b.Degree() {
		newP := &Polynomial{
			fieldOrder:   p.fieldOrder,
			coefficients: newPCoeff,
		}
		newP.SetConstant(big.NewInt(0))
		return newP, p
	}
	m := p.Degree() - b.Degree()
	// call invert() (algorithm 9.3) to compute the inverse of rev deg b (b) belongs to D[x] mod x^{m+1}
	l := big.NewInt(int64(m) + 1)
	RevB := b.rev(b.Degree())
	invRevB := RevB.invert(l)
	qAsterisk := p.rev(p.Degree()).mul(invRevB).rem(int(m) + 1)
	q = qAsterisk.rev(m)
	r = p.minus(b.mul(q))
	return q, r
}
