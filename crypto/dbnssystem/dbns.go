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

package dbnssystem

import (
	"errors"
	"math/big"
)

var (
	big1 = big.NewInt(1)
	big3 = big.NewInt(3)

	// ErrDBNSBase2And3 is returned if the integer can not represented by any linear combination 2^a3^b.
	ErrDBNSBase2And3 = errors.New("not represented by any linear combination 2^a3^b")
	// ErrPositiveInteger is returned if the integer is negative.
	ErrPositiveInteger = errors.New("not a negative integer")
)

/*
This algorithm comes from: A Tree-Based Approach for Computing Double-Base Chains: Algorithm 1. Tree-based DB-chain search.

	This implementation maybe be improved.
	ex: We write 841232 = 2^7*3^8+2^6*3^3-2^5*3^2-2^4.
	Use ExpansionBase2And will get the output is (2-exponent, 3-exponent, sign) = (7,8,1) & (6,3,1) & (5,2,-1) & (4,0,-1).
	Note that: This representations is not unique.
*/
type expansion23 struct {
	exponent2 int
	exponent3 int
	sign      int
}

// Because we need to compute N/3 for some positive integers. We use a small trick transit it to multiply magicIntegerDivide3 for efficiency.
// This idea can be found in book: Hacker's Delight" by Henry Warren.
// The deepOfBench means the max depth generating from a root number. More details can see paper:
// A Tree-Based Approach for Computing Double-Base Chains: Algorithm 1. Tree-based DB-chain search..
type dbnsMentor struct {
	deepOfBranch int
}

func NewDBNS(deepOfBranch int) *dbnsMentor {
	return &dbnsMentor{
		deepOfBranch: deepOfBranch,
	}
}

// Give a, b, discriminant to construct quadratic forms.
func newexpansion23(exponent2, exponent3, s int) *expansion23 {
	return &expansion23{
		exponent2: exponent2,
		exponent3: exponent3,
		sign:      s,
	}
}

func (expan *expansion23) GetExp2() int {
	return expan.exponent2
}
func (expan *expansion23) GetExp3() int {
	return expan.exponent3
}
func (expan *expansion23) GetSign() int {
	return expan.sign
}

// This is a algorithm to get number % 3. The velocity of this function is faster than new(bigInt).mod(number, 3).
func fastMod3(number *big.Int) int {
	numberOne, numberTwo := 0, 0
	for i := 0; i < number.BitLen(); i = i + 2 {
		if number.Bit(i) != 0 {
			numberOne++
		}
	}
	for i := 1; i < number.BitLen(); i = i + 2 {
		if number.Bit(i) != 0 {
			numberTwo++
		}
	}
	result := 0
	if numberOne > numberTwo {
		result = numberOne - numberTwo
	} else {
		result = numberTwo - numberOne
		result = result << 1
	}
	return result % 3
}

func (dbns *dbnsMentor) ExpansionBase2And3(number *big.Int) ([]*expansion23, error) {
	numberClone := new(big.Int).Set(number)
	exp2, exp3 := 0, 0
	numberClone, exp2 = getMax2Factor(numberClone)
	numberClone, exp3 = getMax3Factor(numberClone)
	firstExpansion23 := newexpansion23(exp2, exp3, 0)
	result := []*expansion23{firstExpansion23}
	otherPart, err := get23ExpansionSpecialcase(numberClone, dbns.deepOfBranch)
	if err != nil {
		return nil, err
	}
	result = append(result, otherPart...)
	result = transDBNSForm(result)
	return result, nil
}

func get23ExpansionSpecialcase(numberwithout23Factor *big.Int, deepOfBranch int) ([]*expansion23, error) {
	result := make([]*expansion23, 0)
	for numberwithout23Factor.Cmp(big1) != 0 {
		value, tempExpansion23, err := getGivenDepth23Expansion(numberwithout23Factor, deepOfBranch)
		if err != nil {
			return nil, err
		}
		numberwithout23Factor = value
		result = append(result, tempExpansion23...)
	}
	return result, nil
}

func getGivenDepth23Expansion(number *big.Int, upperDepth int) (*big.Int, []*expansion23, error) {
	numberList := []*big.Int{number}
	minPosition, exp2, exp3 := 0, 0, 0
	upperDepthMinus1 := uint(upperDepth - 1)
	var bStop bool
	minValue := new(big.Int).Set(number)
	if number.Sign() < 1 {
		return nil, nil, ErrPositiveInteger
	}
	number, exp2 = getMax2Factor(number)
	_, exp3 = getMax3Factor(number)
	totalSlice := []*expansion23{newexpansion23(exp2, exp3, 0)}

	for j := uint(0); j < upperDepthMinus1; j++ {
		index, upperBound := (1<<j)-1, (1<<(j+1))-1
		for i := index; i < upperBound; i++ {
			bStop, totalSlice, numberList = bStopComputeDescendent(totalSlice, numberList, i)
			if bStop {
				return big1, totalSlice, nil
			}
		}
	}
	index, upperBound := (1<<upperDepthMinus1)-1, (1<<(upperDepthMinus1+1))-1
	for i := index; i < upperBound; i++ {
		bStop, totalSlice, numberList = bStopComputeDescendent(totalSlice, numberList, i)
		if bStop {
			return big1, totalSlice, nil
		}
		// numberList[len(numberList)-2] := minus1 and numberList[len(numberList)-1] = plus1
		minValue, minPosition = getMinValueAndPosition(minValue, numberList[len(numberList)-2], numberList[len(numberList)-1], minPosition, i)
	}
	return minValue, getRepresentation23Expansion(minPosition, totalSlice), nil
}

// For the newest branch, we find the minimal value to set it to be new startpoint. And use its location to trace the corresponding factors.
func getMinValueAndPosition(nowMinValue, compareMinus1Value, comparePlus1Value *big.Int, minPosition, index int) (*big.Int, int) {
	position := ((index + 1) << 1)
	if nowMinValue.Cmp(compareMinus1Value) > 0 {
		nowMinValue = compareMinus1Value
		minPosition = position
	}
	if nowMinValue.Cmp(comparePlus1Value) > 0 {
		position++
		minPosition = position
		nowMinValue = comparePlus1Value
	}
	return nowMinValue, minPosition
}

func bStopComputeDescendent(totalSlice []*expansion23, numberList []*big.Int, index int) (bool, []*expansion23, []*big.Int) {
	plus1, minus1, factor23 := computePlus1AndMinus123Factor(numberList[index])
	totalSlice = append(totalSlice, factor23...)
	if minus1.Cmp(big1) == 0 {
		position := ((index + 1) << 1)
		return true, getRepresentation23Expansion(position, totalSlice), nil
	}
	if plus1.Cmp(big1) == 0 {
		position := ((index + 1) << 1) + 1
		return true, getRepresentation23Expansion(position, totalSlice), nil
	}
	numberList = append(numberList, minus1)
	numberList = append(numberList, plus1)
	return false, totalSlice, numberList
}

// assume that gcd(number,6) = 1
func computePlus1AndMinus123Factor(number *big.Int) (*big.Int, *big.Int, []*expansion23) {
	result := make([]*expansion23, 0)
	exp2, exp3 := 0, 0
	numberMinus1 := new(big.Int).Sub(number, big1)
	numberMinus1, exp2 = getMax2Factor(numberMinus1)
	numberMinus1, exp3 = getMax3Factor(numberMinus1)
	temp23FactorMinus1 := newexpansion23(exp2, exp3, -1)
	result = append(result, temp23FactorMinus1)

	numberPlus1 := new(big.Int).Add(number, big1)
	numberPlus1, exp2 = getMax2Factor(numberPlus1)
	numberPlus1, exp3 = getMax3Factor(numberPlus1)
	temp23FactorPlus1 := newexpansion23(exp2, exp3, 1)
	result = append(result, temp23FactorPlus1)
	return numberPlus1, numberMinus1, result
}

func getRepresentation23Expansion(position int, totalSlice []*expansion23) []*expansion23 {
	result := make([]*expansion23, 0)
	copyPosition := position - 1
	for copyPosition > 0 {
		addSlice := []*expansion23{totalSlice[copyPosition]}
		result = append(addSlice, result...)
		copyPosition = (copyPosition - 1) >> 1
	}
	return result
}

func getMax2Factor(number *big.Int) (*big.Int, int) {
	bitLength := number.BitLen()
	for i := 0; i < bitLength; i++ {
		if number.Bit(i) != 0 {
			number.Rsh(number, uint(i))
			return number, i
		}
	}
	return big.NewInt(0), 0
}

func getMax3Factor(number *big.Int) (*big.Int, int) {
	bitLength := number.BitLen()
	for i := 0; i < bitLength; i++ {
		residue := fastMod3(number)
		if residue == 0 {
			number.Div(number, big3)
			continue
		}
		return number, i
	}
	return nil, 0
}

// example: The input of the struct is like: 841232 = 2^4(2^5(2^2*3^1(2^3(2^4+1)+1)−1)+1)
// The output is 841232 = 2^18*3^1+2^14*3^1−2^11*3^1+2^9+2^4
func transDBNSForm(input []*expansion23) []*expansion23 {
	result := make([]*expansion23, len(input))
	exp2, exp3 := 0, 0
	length := len(input) - 1
	for i := 0; i < length; i++ {
		exp2 += input[i].exponent2
		exp3 += input[i].exponent3
		temp := newexpansion23(exp2, exp3, -1*input[i+1].sign)
		result[length-i] = temp
	}
	exp2 += input[length].exponent2
	exp3 += input[length].exponent3
	result[0] = newexpansion23(exp2, exp3, 1)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}
