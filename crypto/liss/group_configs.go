// Copyright © 2021 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.gc/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package liss

import (
	"math"
	"math/big"
	"sort"
	"strconv"

	bqForm "github.com/getamis/alice/crypto/binaryquadraticform"
	"github.com/getamis/alice/crypto/matrix"
	"github.com/getamis/alice/crypto/utils"
)

var (
	big1 = big.NewInt(1)
)

type GroupConfigs []*GroupConfig

// The output is randomValueMatrix, organizationMatrix
func (gc GroupConfigs) GenerateShares(g bqForm.Exper, randomM *matrix.Matrix, orgMatrix *matrix.Matrix) ([][]map[string]*big.Int, []*bqForm.BQuadraticForm, error) {
	copyOrg := orgMatrix.Copy()
	sharesMatrix, err := copyOrg.Multiply(randomM)
	if err != nil {
		return nil, nil, err
	}
	shareSlice := sharesMatrix.GetMatrix()

	// Build shares, per group, per user
	shares := make([][]map[string]*big.Int, len(gc))
	index := 0
	for i := 0; i < len(gc); i++ {
		shares[i] = make([]map[string]*big.Int, gc[i].Users)
		for j := 0; j < gc[i].Users; j++ {
			shares[i][j] = make(map[string]*big.Int)
		}
		combination := gc[i].Combinations()
		for _, value := range combination {
			key := ShareKey(value)
			for j := 0; j < gc[i].Threshold; j++ {
				shares[i][value[j]][key] = shareSlice[index][0]
				index++
			}
		}
	}

	// Build exponentialM
	exponentialM := make([]*bqForm.BQuadraticForm, orgMatrix.GetNumberRow())
	for i := 0; i < len(exponentialM); i++ {
		exponentialM[i], err = g.Exp(sharesMatrix.Get(uint64(i), 0))
		if err != nil {
			return nil, nil, err
		}
	}
	return shares, exponentialM, nil
}

func (gc GroupConfigs) GetCommitmentOrderBySerialNumber(expM []*bqForm.BQuadraticForm) [][]map[string]*bqForm.BQuadraticForm {
	commitments := make([][]map[string]*bqForm.BQuadraticForm, len(gc))
	index := 0
	for i := 0; i < len(gc); i++ {
		commitments[i] = make([]map[string]*bqForm.BQuadraticForm, gc[i].Users)
		for j := 0; j < gc[i].Users; j++ {
			commitments[i][j] = make(map[string]*bqForm.BQuadraticForm)
		}
		combination := gc[i].Combinations()
		for _, value := range combination {
			key := ShareKey(value)
			for j := 0; j < gc[i].Threshold; j++ {
				commitments[i][value[j]][key] = expM[index]
				index++
			}
		}
	}
	return commitments
}

func ShareKey(input sort.IntSlice) string {
	// Force to sort the input again to ensure make the same key
	sort.Sort(input)

	result := strconv.Itoa(input[0])
	for i := 1; i < len(input); i++ {
		result += ","
		text := strconv.Itoa(input[i])
		result += text
	}
	return result
}

func (gc GroupConfigs) GenerateRandomValue(bigrange uint, distanceDist uint) (*matrix.Matrix, *matrix.Matrix, error) {
	m, err := gc.generateMatrix()
	if err != nil {
		return nil, nil, err
	}
	// upBd = bigrange + \ceil log2(e-1) \ceil + 1 + distanceDist
	rankBound := math.Ceil(math.Log2(float64(m.GetNumberColumn()))) + 1
	upBd := new(big.Int).Lsh(big1, bigrange+distanceDist+uint(rankBound))
	randomValueMatrix := make([][]*big.Int, m.GetNumberColumn())
	secretSlice := make([]*big.Int, 1)
	secretSlice[0], err = utils.RandomAbsoluteRangeInt(new(big.Int).Lsh(big1, bigrange))
	if err != nil {
		return nil, nil, err
	}
	randomValueMatrix[0] = secretSlice
	for i := 1; i < len(randomValueMatrix); i++ {
		tempSlice := make([]*big.Int, 1)
		tempSlice[0], err = utils.RandomAbsoluteRangeInt(upBd)
		if err != nil {
			return nil, nil, err
		}
		randomValueMatrix[i] = tempSlice
	}
	result, err := matrix.NewMatrix(nil, randomValueMatrix)
	if err != nil {
		return nil, nil, err
	}
	return result, m, nil
}

func (gc GroupConfigs) generateMatrix() (*matrix.Matrix, error) {
	result, err := gc[0].GenerateMatrix()
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(gc); i++ {
		temp, err := gc[i].GenerateMatrix()
		if err != nil {
			return nil, err
		}
		result, err = andMatrix(result, temp)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
