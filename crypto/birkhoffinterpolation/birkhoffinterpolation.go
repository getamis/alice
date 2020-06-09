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

package birkhoffinterpolation

import (
	"errors"
	fmt "fmt"
	"math/big"
	"sort"

	"github.com/getamis/alice/crypto/matrix"
	"github.com/getamis/alice/crypto/utils"
	"gonum.org/v1/gonum/stat/combin"
)

var (
	//ErrEqualOrLargerThreshold is returned if threshold is equal or larger than the length of Bk parameters
	ErrEqualOrLargerThreshold = errors.New("equal or larger threshold")
	//ErrInvalidBks is returned if it exists a pair of invalid bks
	ErrInvalidBks = errors.New("invalid bks")
	//ErrNoValidBks is returned if there's no valid bk
	ErrNoValidBks = errors.New("no valid bks")
	//ErrNoExistBk is returned if there does not exist bk
	ErrNoExistBk = errors.New("no exist bk")
)

type BkParameter struct {
	x    *big.Int
	rank uint32
}

func NewBkParameter(x *big.Int, rank uint32) *BkParameter {
	return &BkParameter{
		x:    x,
		rank: rank,
	}
}

func (p *BkParameter) GetX() *big.Int {
	return p.x
}

func (p *BkParameter) GetRank() uint32 {
	return p.rank
}

func (p *BkParameter) String() string {
	return fmt.Sprintf("(x, rank) = (%s, %d)", p.x, p.rank)
}

func (p *BkParameter) GetLinearEquationCoefficient(fieldOrder *big.Int, degreePoly uint32) []*big.Int {
	result := make([]*big.Int, degreePoly+1)
	for i := uint32(0); i < uint32(len(result)); i++ {
		result[i] = p.getDiffMonomialCoeff(fieldOrder, i)
	}
	return result
}

func (p *BkParameter) ToMessage() *BkParameterMessage {
	return &BkParameterMessage{
		X:    p.x.Bytes(),
		Rank: p.rank,
	}
}

// Consider a monomial x^n where n is the degree. Then output is n*(n_1)*...*(n-diffTime+1)*x^{degree-diffTimes}|_{x}
// Example:x^5, diffTime = 2 and x =3 Then output is 3^(3)*5*4
func (p *BkParameter) getDiffMonomialCoeff(fieldOrder *big.Int, degree uint32) *big.Int {
	if degree < p.rank {
		return big.NewInt(0)
	}
	if degree == 0 {
		return big.NewInt(1)
	}
	// Get extra coefficient
	tempValue := uint32(1)
	for j := uint32(0); j < p.rank; j++ {
		tempValue *= (degree - j)
	}
	extraValue := new(big.Int).SetUint64(uint64(tempValue))
	// x^{degree-diffTimes}
	power := new(big.Int).SetUint64(uint64(degree - p.rank))
	result := new(big.Int).Exp(p.x, power, fieldOrder)
	return result.Mul(result, extraValue)
}

type BkParameters []*BkParameter

// Compare rank and then x
// Let bk := (rank, x). Then if (rank1, x1) > (rank2,x2) iff rank1<rank2 or ( rank1=rank2 and x1>x2)
func (bks BkParameters) Less(i, j int) bool {
	if bks[i].rank < bks[j].rank {
		return true
	}
	if bks[i].rank > bks[j].rank {
		return false
	}
	return bks[i].x.Cmp(bks[j].x) < 0
}

func (bks BkParameters) Len() int {
	return len(bks)
}

func (bks BkParameters) Swap(i, j int) {
	bks[i], bks[j] = bks[j], bks[i]
}

func (bks BkParameters) CheckValid(threshold uint32, fieldOrder *big.Int) error {
	if err := bks.ensureRankAndOrder(threshold, fieldOrder); err != nil {
		return err
	}

	// Deep copy and sort the pk slice
	sortedBks := make(BkParameters, bks.Len())
	copy(sortedBks, bks)
	sort.Sort(sortedBks)

	// Get all combinations of C(threshold, len(ps)).
	enoughRank := false
	combination := combin.Combinations(sortedBks.Len(), int(threshold))
	for i := 0; i < len(combination); i++ {
		tempBks := BkParameters{}
		for j := 0; j < len(combination[i]); j++ {
			tempBks = append(tempBks, sortedBks[combination[i][j]])
		}
		// Ensuring the set of shares with enough rank and enough threshold has ability to recover secret.
		if !tempBks.isEnoughRank() {
			continue
		}

		enoughRank = true
		birkhoffMatrix, err := tempBks.getLinearEquationCoefficientMatrix(threshold, fieldOrder)
		if err != nil {
			return err
		}
		rankBirkhoffMatrix, err := birkhoffMatrix.GetMatrixRank(fieldOrder)
		if err != nil {
			return err
		}
		if rankBirkhoffMatrix != uint64(threshold) {
			return ErrInvalidBks
		}
	}
	if !enoughRank {
		return ErrNoValidBks
	}
	return nil
}

// isEnoughRank checks if the set of ranks can recover secret
func (bks BkParameters) isEnoughRank() bool {
	for i := 0; i < bks.Len(); i++ {
		if bks[i].rank > uint32(i) {
			return false
		}
	}
	return true
}

// ComputeBkCoefficient returns the bk coefficients from parameters
func (bks BkParameters) ComputeBkCoefficient(threshold uint32, fieldOrder *big.Int) ([]*big.Int, error) {
	if err := bks.ensureRankAndOrder(threshold, fieldOrder); err != nil {
		return nil, err
	}
	return bks.computeBkCoefficient(threshold, fieldOrder)
}

func (bks BkParameters) ensureRankAndOrder(threshold uint32, fieldOrder *big.Int) error {
	if err := utils.EnsureFieldOrder(fieldOrder); err != nil {
		return err
	}
	if uint32(bks.Len()) < threshold {
		return ErrEqualOrLargerThreshold
	}
	return nil
}

func (bks BkParameters) computeBkCoefficient(threshold uint32, fieldOrder *big.Int) ([]*big.Int, error) {
	birkhoffMatrix, err := bks.getLinearEquationCoefficientMatrix(threshold, fieldOrder)
	if err != nil {
		return nil, err
	}
	result, err := birkhoffMatrix.Pseudoinverse()
	if err != nil {
		return nil, err
	}
	return result.GetRow(0)
}

// Establish the coefficient of linear system of Birkhoff systems. The relation of Birkhoff matrix and LinearEquationCoefficientMatrix is
// LinearEquationCoefficientMatrix = the inverse of Birkhoff matrix.
// Assume: share1: diffTime=0, x=1 share2: x=2, diffTime = 1, share3: x =3, differTime=2
// Then output is:
// 1^(diffTime)|_{x}  x^(diffTime)|_{x} (x^2)^(diffTime)|_{x}
// [       1                       1                          1   ] diffTime = 0, x =1
// [       0                       1                          4   ] diffTime = 1, x =2
// [       0                       0                          2   ] diffTime = 2, x =3
// This matrix is called Birkhoff matrix
func (bks BkParameters) getLinearEquationCoefficientMatrix(nThreshold uint32, fieldOrder *big.Int) (*matrix.Matrix, error) {
	lens := bks.Len()
	result := make([][]*big.Int, lens)
	degree := nThreshold - 1
	for i := 0; i < lens; i++ {
		result[i] = bks[i].GetLinearEquationCoefficient(fieldOrder, degree)
	}
	return matrix.NewMatrix(fieldOrder, result)
}

// Compute [sum_{k=newRank}^{t-1} k!/(k-newRank)!(x_new)^(k-newRank)*b_{ki}]*s_i, newRank is the rank of newBk, x_new is x-coordinate of newBk, and b_{ki} is
// the (k,i)-component of the pseudoinverse of Birkhoff matrix associated bks.
func (bks BkParameters) GetAddShareCoefficeint(ownBk, newBk *BkParameter, fieldOrder *big.Int, threshold uint32) (*big.Int, error) {
	birkhoffMatrix, err := bks.getLinearEquationCoefficientMatrix(threshold, fieldOrder)
	if err != nil {
		return nil, err
	}
	birkhoffMatrix, err = birkhoffMatrix.Pseudoinverse()
	if err != nil {
		return nil, err
	}
	ownIndex, err := bks.getIndexOfBK(ownBk)
	if err != nil {
		return nil, err
	}
	newrank := uint64(newBk.rank)
	result := big.NewInt(0)
	xPower := big.NewInt(1)

	// Get newrank!
	newRankFactorial := big.NewInt(1)
	for i := uint64(2); i < newrank+1; i++ {
		newRankFactorial = newRankFactorial.Mul(newRankFactorial, new(big.Int).SetUint64(i))
		newRankFactorial = newRankFactorial.Mod(newRankFactorial, fieldOrder)
	}
	for i := newrank; i < uint64(threshold); i++ {
		factorialCoe := new(big.Int).Binomial(int64(i), int64(i-newrank))
		factorialCoe = factorialCoe.Mul(factorialCoe, newRankFactorial)
		tempbki := birkhoffMatrix.Get(uint64(i), uint64(ownIndex))
		tempResult := new(big.Int).Mul(factorialCoe, xPower)
		tempResult = tempResult.Mul(tempResult, tempbki)
		result = result.Add(tempResult, result)
		result = result.Mod(result, fieldOrder)
		xPower = xPower.Mul(xPower, newBk.GetX())
	}
	return result, nil
}

func (bks BkParameters) getIndexOfBK(ownBk *BkParameter) (int, error) {
	for i := 0; i < len(bks); i++ {
		if bks[i].GetX().Cmp(ownBk.GetX()) != 0 {
			continue
		}
		if bks[i].GetRank() == ownBk.rank {
			return i, nil
		}
	}
	return 0, ErrNoExistBk
}
