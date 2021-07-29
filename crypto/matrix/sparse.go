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

func NewCSR(numberRow, numberColumn uint64, fieldOrder *big.Int, value []*big.Int, columnIdx, rowIdx []uint64) *CSR {
	return &CSR{
		fieldOrder:   fieldOrder,
		numberRow:    numberRow,
		numberColumn: numberColumn,
		value:        value,
		columnIdx:    columnIdx,
		rowIdx:       rowIdx,
	}
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
	result := NewCSR(m.numberRow, m.numberColumn, nil, value, columnIndex, rowIndex)
	if m.fieldOrder != nil {
		result.fieldOrder = m.fieldOrder
	}
	return result
}

func (c *CSR) GetValue() []*big.Int {
	return c.value
}

func (c *CSR) GetColumnIdx() []uint64 {
	return c.columnIdx
}

func (c *CSR) GetRowIdx() []uint64 {
	return c.rowIdx
}

func (c *CSR) GetNumberRow() uint64 {
	return c.numberRow
}

func (c *CSR) GetNumberColumn() uint64 {
	return c.numberColumn
}

func (c *CSR) GetFieldOrder() *big.Int {
	if c.fieldOrder != nil {
		return c.fieldOrder
	}
	return nil
}

func (c *CSR) GetRow(nIndex uint64) ([]*big.Int, error) {
	if nIndex >= c.numberRow {
		return nil, ErrOutOfRange
	}
	result := make([]*big.Int, c.GetNumberColumn())
	for i := 0; i < len(result); i++ {
		result[i] = big.NewInt(0)
	}

	for k := c.rowIdx[nIndex]; k < c.rowIdx[nIndex+1]; k++ {
		result[c.columnIdx[k]] = c.value[k]
	}
	return result, nil
}

func (c *CSR) Copy() *CSR {
	copyValue := make([]*big.Int, len(c.value))
	copyColumnIdx := make([]uint64, len(c.columnIdx))
	copyRowIdx := make([]uint64, len(c.rowIdx))

	for i := 0; i < len(copyValue); i++ {
		copyValue[i] = new(big.Int).Set(c.value[i])
		copyColumnIdx[i] = c.columnIdx[i]
	}
	for i := 0; i < len(copyRowIdx); i++ {
		copyRowIdx[i] = c.rowIdx[i]
	}
	if c.fieldOrder != nil {
		return NewCSR(c.numberRow, c.numberColumn, c.fieldOrder, copyValue, copyColumnIdx, copyRowIdx)
	}
	return NewCSR(c.numberRow, c.numberColumn, nil, copyValue, copyColumnIdx, copyRowIdx)
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
