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

package matrix

import (
	"errors"
	"math/big"
)

var (
	// ErrNotVector is returned if the matrix is not a vector
	ErrNotVector = errors.New("not a vector")
)

// Matrix is the struct for Compressed sparse row form
type CSR struct {
	fieldOrder   *big.Int
	numberRow    uint64
	numberColumn uint64

	value     []*big.Int
	columnIdx []uint64
	rowIdx    []uint64
}

// Get the number of non-zero value in the matrix m
func (m *Matrix) NNZ() uint64 {
	result := uint64(0)
	for i := uint64(0); i < m.numberRow; i++ {
		for j := uint64(0); j < m.numberColumn; j++ {
			if m.Get(i, j).Cmp(big0) != 0 {
				result += 1
			}
		}
	}
	return result
}

func (m *Matrix) ToCSR() *CSR {
	NNZ := m.NNZ()
	value := make([]*big.Int, NNZ)
	columnIndex := make([]uint64, NNZ)
	rowIndex := make([]uint64, m.numberRow+1)

	index := uint64(0)
	rowIndex[0] = 0
	for i := uint64(0); i < m.numberRow; i++ {
		for j := uint64(0); j < m.numberColumn; j++ {
			if m.Get(i, j).Cmp(big0) != 0 {
				value[index] = m.Get(i, j)
				columnIndex[index] = j
				index++
			}
		}
		rowIndex[i+1] = index
	}
	result := &CSR{
		fieldOrder:   nil,
		numberRow:    m.numberRow,
		numberColumn: m.numberColumn,
		value:        value,
		columnIdx:    columnIndex,
		rowIdx:       rowIndex,
	}
	if m.fieldOrder != nil {
		result.fieldOrder = m.fieldOrder
	}
	return result
}

func (c *CSR) MultiplyVector(vector *Matrix) (*Matrix, error) {
	if vector.numberColumn != 1 {
		return nil, ErrNotVector
	}
	resultMatrix := make([][]*big.Int, c.numberRow)
	for i := uint64(0); i < c.numberRow; i++ {
		tempResult := big.NewInt(0)
		for k := c.rowIdx[i]; k < c.rowIdx[i+1]; k++ {
			tempMul := new(big.Int).Mul(c.value[k], vector.matrix[c.columnIdx[k]][0])
			tempResult.Add(tempResult, tempMul)
		}
		resultMatrix[i] = []*big.Int{tempResult}
	}
	result, err := NewMatrix(c.fieldOrder, resultMatrix)
	if err != nil {
		return nil, err
	}
	return result.modulus(), nil
}
