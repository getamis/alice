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

func (g *GroupConfig) GenerateMatrix() (*matrix.Matrix, error) {
	thresholdMatrix, err := generateThresholdMatrix(g.Threshold)
	if err != nil {
		return nil, err
	}
	combination := combin.Binomial(g.Users, g.Threshold)
	result := thresholdMatrix.Copy()
	for i := 1; i < combination; i++ {
		result, err = orMatrix(result, thresholdMatrix.Copy())
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func generateThresholdMatrix(threshold int) (*matrix.Matrix, error) {
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
	return matrix.NewMatrix(nil, result)
}

func orMatrix(m1 *matrix.Matrix, m2 *matrix.Matrix) (*matrix.Matrix, error) {
	result := make([][]*big.Int, m1.GetNumberRow()+m2.GetNumberRow())
	numberColumn := int(m1.GetNumberColumn() + m2.GetNumberColumn() - 1)
	m1NumberColumn := int(m1.GetNumberColumn())
	for i := 0; i < int(m1.GetNumberRow()); i++ {
		temp := make([]*big.Int, numberColumn)
		for j := 0; j < int(m1.GetNumberColumn()); j++ {
			temp[j] = m1.Get(uint64(i), uint64(j))
		}
		for j := int(m1.GetNumberColumn()); j < numberColumn; j++ {
			temp[j] = big.NewInt(0)
		}
		result[i] = temp
	}
	for i := 0; i < int(m2.GetNumberRow()); i++ {
		temp := make([]*big.Int, numberColumn)
		temp[0] = m2.Get(uint64(i), 0)
		for j := 1; j < int(m1.GetNumberColumn()); j++ {
			temp[j] = big.NewInt(0)
		}
		for j := 1; j < int(m2.GetNumberColumn()); j++ {
			temp[j+m1NumberColumn-1] = m2.Get(uint64(i), uint64(j))
		}
		result[i+int(m1.GetNumberRow())] = temp
	}
	return matrix.NewMatrix(nil, result)
}

func andMatrix(m1 *matrix.Matrix, m2 *matrix.Matrix) (*matrix.Matrix, error) {
	result := make([][]*big.Int, m1.GetNumberRow()+m2.GetNumberRow())
	numberColumn := int(m1.GetNumberColumn() + m2.GetNumberColumn())
	m1NumberColumn := int(m1.GetNumberColumn())
	for i := 0; i < int(m1.GetNumberRow()); i++ {
		temp := make([]*big.Int, numberColumn)
		temp[0] = m1.Get(uint64(i), 0)
		for j := 0; j < int(m1.GetNumberColumn()); j++ {
			temp[j+1] = m1.Get(uint64(i), uint64(j))
		}
		for j := int(m1.GetNumberColumn()) + 1; j < numberColumn; j++ {
			temp[j] = big.NewInt(0)
		}
		result[i] = temp
	}
	for i := 0; i < int(m2.GetNumberRow()); i++ {
		temp := make([]*big.Int, numberColumn)
		temp[0] = big.NewInt(0)
		temp[1] = m2.Get(uint64(i), 0)
		for j := 1; j < int(m1.GetNumberColumn()); j++ {
			temp[j+1] = big.NewInt(0)
		}
		for j := 1; j < int(m2.GetNumberColumn()); j++ {
			temp[j+m1NumberColumn] = m2.Get(uint64(i), uint64(j))
		}
		result[i+int(m1.GetNumberRow())] = temp
	}
	return matrix.NewMatrix(nil, result)
}
