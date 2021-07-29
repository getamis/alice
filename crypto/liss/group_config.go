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

package liss

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/matrix"
	"gonum.org/v1/gonum/stat/combin"
)

type Mapper interface {
	Has(key string) bool
	Len() int
}

var (
	ErrInvalidUsersOrThreshold = errors.New("invalid users or threshold")
)

type GroupConfig struct {
	// The number of users in this group
	Users int
	// The Threshold of this group
	Threshold int
}

func NewGroup(users int, threshold int) (*GroupConfig, error) {
	if threshold > users || users < 0 {
		return nil, ErrInvalidUsersOrThreshold
	}
	return &GroupConfig{
		Users:     users,
		Threshold: threshold,
	}, nil
}

func (g *GroupConfig) GenerateMatrix() (*matrix.CSR, error) {
	thresholdMatrix, err := generateThresholdMatrix(g.Threshold)
	if err != nil {
		return nil, err
	}
	combination := combin.Binomial(g.Users, g.Threshold)
	result := thresholdMatrix.Copy()
	for i := 1; i < combination; i++ {
		result = orMatrixCSR(result, thresholdMatrix.Copy())
	}
	return result, nil
}

func (g *GroupConfig) Combinations() [][]int {
	return combin.Combinations(g.Users, g.Threshold)
}

func (g *GroupConfig) CheckKeys(userIndex int, m Mapper) bool {
	if g.Threshold > m.Len() {
		return false
	}
	combination := g.Combinations()
	for _, value := range combination {
		key := ShareKey(value)
		for j := 0; j < g.Threshold; j++ {
			if value[j] != userIndex {
				continue
			}
			// Cannot find key
			if !m.Has(key) {
				return false
			}
		}
	}
	return true
}

// To Do: Directly generate CSR form
func generateThresholdMatrix(threshold int) (*matrix.CSR, error) {
	result := make([][]*big.Int, threshold)
	firstRow := make([]*big.Int, threshold)
	for j := 0; j < len(firstRow); j++ {
		firstRow[j] = big.NewInt(1)
	}
	result[0] = firstRow
	nonVanishPosition := len(result) - 1
	for i := 1; i < len(result); i++ {
		temp := make([]*big.Int, threshold)
		for j := 0; j < len(temp); j++ {
			if j != nonVanishPosition {
				temp[j] = big.NewInt(0)
			} else {
				temp[j] = big.NewInt(1)
			}
		}
		nonVanishPosition -= 1
		result[i] = temp
	}
	m, err := matrix.NewMatrix(nil, result)
	if err != nil {
		return nil, err
	}
	return m.ToCSR(), nil
}

func orMatrixCSR(m1 *matrix.CSR, m2 *matrix.CSR) *matrix.CSR {
	m1ColumnIdx := m1.GetColumnIdx()
	numberNonZero := len(m1.GetValue()) + len(m2.GetValue())
	value := make([]*big.Int, numberNonZero)
	columnIdx := make([]uint64, numberNonZero)
	rowIdx := make([]uint64, m1.GetNumberRow()+m2.GetNumberRow()+1)
	rowIdx[0] = 0
	m1Value := m1.GetValue()
	m1RowIdx := m1.GetRowIdx()
	index := uint64(0)
	for i := uint64(0); i < m1.GetNumberRow(); i++ {
		for k := m1RowIdx[i]; k < m1RowIdx[i+1]; k++ {
			if m1ColumnIdx[k] == 0 {
				value[index] = m1Value[k]
				columnIdx[index] = 0
				index++
			} else {
				value[index] = m1Value[k]
				columnIdx[index] = m1ColumnIdx[k]
				index++
			}
		}
		rowIdx[i+1] = index
	}
	m2Value := m2.GetValue()
	m2RowIdx := m2.GetRowIdx()
	m2ColumnIdx := m2.GetColumnIdx()
	translate := m1.GetNumberColumn() - 1
	translateIndex := m1.GetNumberRow() + 1
	for i := uint64(0); i < m2.GetNumberRow(); i++ {
		for k := m2RowIdx[i]; k < m2RowIdx[i+1]; k++ {
			if m2ColumnIdx[k] == 0 {
				value[index] = m2Value[k]
				columnIdx[index] = 0
				index++
			} else {
				value[index] = m2Value[k]
				columnIdx[index] = m2ColumnIdx[k] + translate
				index++
			}
		}
		rowIdx[translateIndex+i] = index
	}
	return matrix.NewCSR(m1.GetNumberRow()+m2.GetNumberRow(), m1.GetNumberColumn()+m2.GetNumberColumn()-1, nil, value, columnIdx, rowIdx)
}

func andMatrixCSR(m1 *matrix.CSR, m2 *matrix.CSR) *matrix.CSR {
	nonzeroIndex0 := 0
	m1ColumnIdx := m1.GetColumnIdx()
	for i := 0; i < len(m1ColumnIdx); i++ {
		if m1ColumnIdx[i] == 0 {
			nonzeroIndex0++
		}
	}
	numberNonZero := nonzeroIndex0 + len(m1.GetValue()) + len(m2.GetValue())
	value := make([]*big.Int, numberNonZero)
	columnIdx := make([]uint64, numberNonZero)
	rowIdx := make([]uint64, m1.GetNumberRow()+m2.GetNumberRow()+1)
	rowIdx[0] = 0
	m1Value := m1.GetValue()
	m1RowIdx := m1.GetRowIdx()
	index := uint64(0)
	for i := uint64(0); i < m1.GetNumberRow(); i++ {
		for k := m1RowIdx[i]; k < m1RowIdx[i+1]; k++ {
			if m1ColumnIdx[k] == 0 {
				value[index] = m1Value[k]
				columnIdx[index] = 0
				index++
				value[index] = m1Value[k]
				columnIdx[index] = 1
				index++
			} else {
				value[index] = m1Value[k]
				columnIdx[index] = m1ColumnIdx[k] + 1
				index++
			}
		}
		rowIdx[i+1] = index
	}
	m2Value := m2.GetValue()
	m2RowIdx := m2.GetRowIdx()
	m2ColumnIdx := m2.GetColumnIdx()
	translate := m1.GetNumberColumn()
	translateIndex := m1.GetNumberRow() + 1
	for i := uint64(0); i < m2.GetNumberRow(); i++ {
		for k := m2RowIdx[i]; k < m2RowIdx[i+1]; k++ {
			if m2ColumnIdx[k] == 0 {
				value[index] = m2Value[k]
				columnIdx[index] = 1
				index++
			} else {
				value[index] = m2Value[k]
				columnIdx[index] = m2ColumnIdx[k] + translate
				index++
			}
		}
		rowIdx[translateIndex+i] = index
	}
	return matrix.NewCSR(m1.GetNumberRow()+m2.GetNumberRow(), m1.GetNumberColumn()+m2.GetNumberColumn(), nil, value, columnIdx, rowIdx)
}
