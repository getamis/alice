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

// RandomPolynomialWithSpecialValueAtPoint gives a random polynomial f with the given degree with the condition: f(x) = specialValue.
func RandomPolynomialWithSpecialValueAtPoint(x *big.Int, specialValue *big.Int, fieldOrder *big.Int, degree uint32) (*Polynomial, error) {
	p, err := RandomPolynomial(fieldOrder, degree)
	if err != nil {
		return nil, err
	}
	return p.expend(x, specialValue)
}

// Ex: Let coefficient = [1,2,3], givenPoint = 5. Then the output is 3(x-5)^2 + 2(x-5)+1
func (p *Polynomial) expend(xpoint, givenPoint *big.Int) (*Polynomial, error) {
	givenPointPower := make([]*big.Int, len(p.coefficients))
	givenPointPower[0] = big.NewInt(1)
	for i := 1; i < len(givenPointPower); i++ {
		givenPointPower[i] = new(big.Int).Mul(givenPointPower[i-1], xpoint)
	}
	newCos := make([]*big.Int, len(p.coefficients))
	newCos[0] = new(big.Int).Set(givenPoint)
	for i := 1; i < len(newCos); i++ {
		newCos[i] = big.NewInt(0)
	}
	for i := uint32(1); i < uint32(len(newCos)); i++ {
		tempResult := expandMonomial(p.coefficients[i], givenPointPower, i)
		for j := 0; j < len(tempResult); j++ {
			newCos[j].Add(newCos[j], tempResult[j])
		}
	}
	return NewPolynomial(p.fieldOrder, newCos)
}

// Get pascal number. Ex: If degree = 4. The output is [1,4,6,4,1].
func getPascalNumber(degree uint32) []uint64 {
	result := make([]uint64, degree+1)
	result[0] = 1
	n := uint64(degree)
	for i := uint64(0); i <= n/2; i++ {
		result[i+1] = ((result[i]) * (n - i)) / (i + 1)
	}
	for i := n; i > n/2; i-- {
		result[i] = result[n-i]
	}
	return result
}

// Get leadingCoefficient*(x-power[1])^degree.
func expandMonomial(leadingCoefficient *big.Int, power []*big.Int, degree uint32) []*big.Int {
	result := make([]*big.Int, degree+1)
	maxIndex := len(result) - 1
	pascalNumber := getPascalNumber(degree)
	result[maxIndex] = new(big.Int).Set(leadingCoefficient)
	isNeg := true
	for i := maxIndex - 1; i >= 0; i-- {
		tempIndex := maxIndex - i
		tempValue := new(big.Int).Set(power[tempIndex])
		if isNeg {
			tempValue = new(big.Int).Neg(power[tempIndex])
		}
		tempValue.Mul(tempValue, leadingCoefficient)
		tempValue.Mul(tempValue, new(big.Int).SetUint64(pascalNumber[i]))
		result[i] = tempValue
		isNeg = !isNeg
	}
	return result
}
