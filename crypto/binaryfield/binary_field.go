// Copyright © 2021 AMIS Technologies
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

package binaryfield

import (
	"errors"
)

var (
	// ErrWrongInput is returned if the input is wrong
	ErrWrongInput = errors.New("wrong input")
)

// FieldElement represents a value in GF(2¹²⁸).
// the coefficient of x⁰ can be obtained by v.low >> 63.
// the coefficient of x⁶³ can be obtained by v.low & 1.
// the coefficient of x⁶⁴ can be obtained by v.high >> 63.
// the coefficient of x¹²⁷ can be obtained by v.high & 1.
type FieldElement struct {
	low  uint64
	high uint64
}

func NewFieldElement(low, high uint64) *FieldElement {
	return &FieldElement{
		low:  low,
		high: high,
	}
}

// Add adds two elements of GF(2¹²⁸) and returns the sum.
func (x *FieldElement) Add(y *FieldElement) *FieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return NewFieldElement(x.low^y.low, x.high^y.high)
}

func (x *FieldElement) Copy() *FieldElement {
	return NewFieldElement(x.low, x.high)
}

func (x *FieldElement) GetLow() uint64 {
	return x.low
}

func (x *FieldElement) GetHigh() uint64 {
	return x.high
}

func (x *FieldElement) Equal(y *FieldElement) bool {
	if x.low != y.low {
		return false
	}
	if x.high != y.high {
		return false
	}
	return true
}

func AddVector(x, y []*FieldElement) ([]*FieldElement, error) {
	if len(x) != len(y) {
		return nil, ErrWrongInput
	}
	result := make([]*FieldElement, len(x))
	for i := 0; i < len(result); i++ {
		result[i] = x[i].Add(y[i])
	}
	return result, nil
}

func ToFieldElement(xMsg []*BinaryMessage) []*FieldElement {
	result := make([]*FieldElement, len(xMsg))
	for i := 0; i < len(result); i++ {
		result[i] = xMsg[i].ToFieldElement()
	}
	return result
}

func EqualSlice(x, y []*FieldElement) bool {
	if len(x) != len(y) {
		return false
	}
	for i := 0; i < len(x); i++ {
		if !x[i].Equal(y[i]) {
			return false
		}
	}
	return true
}

func TransFieldElementMsg(u []*FieldElement) []*BinaryMessage {
	result := make([]*BinaryMessage, len(u))
	for i := 0; i < len(result); i++ {
		temp := &BinaryMessage{
			Low:  u[i].GetLow(),
			High: u[i].GetHigh(),
		}
		result[i] = temp
	}
	return result
}
