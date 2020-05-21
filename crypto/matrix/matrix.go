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

package matrix

import (
	"errors"
	"math/big"
)

const (
	// maxNumberColumnAndRow defines the max permitted number of columns and rows
	maxNumberColumnAndRow = 100
)

var (
	// ErrNonPrimeFieldOrder is returned if the field order is nonprime
	ErrNonPrimeFieldOrder = errors.New("non prime field order")
	// ErrNilMatrix is returned if it's a nil matrix
	ErrNilMatrix = errors.New("nil matrix")
	// ErrZeroRows is returned if the number of row of the matrix is zero
	ErrZeroRows = errors.New("zero rows")
	// ErrZeroColumns is returned if the number of column of the matrix is zero
	ErrZeroColumns = errors.New("zero columns")
	// ErrInconsistentColumns is returned if the column rank is inconsistent in this matrix
	ErrInconsistentColumns = errors.New("inconsistent columns")
	// ErrZeroOrNegativeRank is returned if the rank is zero or negative
	ErrZeroOrNegativeRank = errors.New("zero or negative rank")
	// ErrOutOfRange is returned if the index is out of the column or row range
	ErrOutOfRange = errors.New("out of range")
	// ErrInconsistentNumber is returned if the two matrixes are the inconsistent number
	ErrInconsistentNumber = errors.New("inconsistent number")
	// ErrNotSquareMatrix is returned if it's not a square matrix
	ErrNotSquareMatrix = errors.New("not a square matrix")
	// ErrNotInvertableMatrix is returned if it's not an invertable matrix
	ErrNotInvertableMatrix = errors.New("not invertable matrix")
	// ErrMaximalSizeOfMatrice is returned if the number of column or row exceeds the given bound
	ErrMaximalSizeOfMatrice = errors.New("the number of column or row exceeds the given bound")

	big0 = big.NewInt(0)
)

// Matrix is the struct for matrix operation
type Matrix struct {
	fieldOrder   *big.Int
	numberRow    uint64
	numberColumn uint64
	matrix       [][]*big.Int
}

// NewMatrix checks the input matrix slices. It returns error if the
// number of rows or columns is zero or the number of column is inconsistent.
func NewMatrix(fieldOrder *big.Int, matrix [][]*big.Int) (*Matrix, error) {
	if fieldOrder == nil || !fieldOrder.ProbablyPrime(1) {
		return nil, ErrNonPrimeFieldOrder
	}
	numberRow := uint64(len(matrix))
	if numberRow == 0 {
		return nil, ErrZeroRows
	}
	numberColumn := uint64(len(matrix[0]))
	if numberColumn == 0 {
		return nil, ErrZeroColumns
	}
	if numberRow >= maxNumberColumnAndRow || numberColumn >= maxNumberColumnAndRow {
		return nil, ErrMaximalSizeOfMatrice
	}
	for i := uint64(0); i < numberRow; i++ {
		if uint64(len(matrix[i])) != numberColumn {
			return nil, ErrInconsistentColumns
		}
		for j := uint64(0); j < numberColumn; j++ {
			if matrix[i][j] == nil {
				return nil, ErrNilMatrix
			}
		}
	}
	return &Matrix{
		fieldOrder:   fieldOrder,
		numberRow:    numberRow,
		numberColumn: numberColumn,
		matrix:       matrix,
	}, nil
}

// Copy returns a copied matrix
func (m *Matrix) Copy() *Matrix {
	return &Matrix{
		fieldOrder:   new(big.Int).Set(m.fieldOrder),
		numberRow:    m.numberRow,
		numberColumn: m.numberColumn,
		matrix:       m.GetMatrix(),
	}
}

func (m *Matrix) GetMatrix() [][]*big.Int {
	newMatrix := make([][]*big.Int, m.numberRow)
	for i := uint64(0); i < m.numberRow; i++ {
		newMatrix[i] = make([]*big.Int, m.numberColumn)
		for j := uint64(0); j < m.numberColumn; j++ {
			newMatrix[i][j] = m.Get(i, j)
		}
	}
	return newMatrix
}

func (m *Matrix) GetNumberColumn() uint64 {
	return m.numberColumn
}

func (m *Matrix) GetNumberRow() uint64 {
	return m.numberRow
}

// GetColumn gets column at the index
// Assume matrixA = [ 1, 2, 3 ]
//                  [ 2, 4, 5 ]
//                  [ 5, 10, 3]
// Then the output of GetColumn(matrixA, nIndex) is the indicated column.
// Ex: GetColumn(matrixA, 2)= [3, 5, 3], GetColumn(matrixA, 1)=[2, 4, 10]
func (m *Matrix) GetColumn(nIndex uint64) ([]*big.Int, error) {
	if nIndex >= m.numberColumn {
		return nil, ErrOutOfRange
	}

	tempSlice := make([]*big.Int, m.numberRow)
	for i := uint64(0); i < m.numberRow; i++ {
		tempSlice[i] = m.Get(i, nIndex)
	}
	return tempSlice, nil
}

// GetRow gets row at the index
// Assume matrixA = [ 1, 2, 3 ]
//                  [ 2, 4, 5 ]
//                  [ 5, 10, 3]
// Then the output of GetColumn(matrixA, nIndex ) is the indicated row.
// Ex: GetRow(matrixA, 2)= [5, 10, 3], GetRow(matrixA, 1)=[2, 4, 5]
func (m *Matrix) GetRow(nIndex uint64) ([]*big.Int, error) {
	if nIndex >= m.numberRow {
		return nil, ErrOutOfRange
	}
	tempSlice := make([]*big.Int, m.numberColumn)
	for i := uint64(0); i < m.numberColumn; i++ {
		tempSlice[i] = m.Get(nIndex, i)
	}
	return tempSlice, nil
}

// Get gets the element at (i, j)
func (m *Matrix) Get(i, j uint64) *big.Int {
	v := m.get(i, j)
	if v == nil {
		return nil
	}
	return new(big.Int).Mod(v, m.fieldOrder)
}

// get gets the element at (i, j) without mod its value
func (m *Matrix) get(i, j uint64) *big.Int {
	if i >= m.numberRow {
		return nil
	}
	if j >= m.numberColumn {
		return nil
	}
	return m.matrix[i][j]
}

func (m *Matrix) modInverse(i, j uint64) *big.Int {
	v := m.get(i, j)
	return new(big.Int).ModInverse(v, m.fieldOrder)
}

// Transpose transposes the matrix
// This function give the transpose of input.
// Ex: A =[ 1, 2  ] (i.e. 1X2 matrix)
// output is [ 1 ] (i.e. 2X1 matrix)
//           [ 2 ]
func (m *Matrix) Transpose() *Matrix {
	transposeMatrix := make([][]*big.Int, m.numberColumn)
	for i := uint64(0); i < m.numberColumn; i++ {
		tempSlice := make([]*big.Int, m.numberRow)

		for j := uint64(0); j < m.numberRow; j++ {
			tempSlice[j] = m.matrix[j][i]
		}
		transposeMatrix[i] = tempSlice
	}
	m.matrix = transposeMatrix

	// Exchange rank
	m.numberColumn, m.numberRow = m.numberRow, m.numberColumn
	return m
}

// Add adds the matrix
// The standard addition of Matrices
func (m *Matrix) Add(matrix *Matrix) (*Matrix, error) {
	if m.numberColumn != matrix.numberColumn || m.numberRow != matrix.numberRow {
		return nil, ErrInconsistentNumber
	}

	for i := uint64(0); i < m.numberRow; i++ {
		m.matrix[i] = addSlices(m.matrix[i], matrix.matrix[i])
	}
	return m.modulus(), nil
}

func (m *Matrix) multiply(matrix *Matrix) (*Matrix, error) {
	// check two matrices can do multiplication by checking their sizes
	if m.numberColumn != matrix.numberRow {
		return nil, ErrInconsistentNumber
	}

	for i := uint64(0); i < m.numberRow; i++ {
		tempSlice := make([]*big.Int, matrix.numberColumn)
		for j := uint64(0); j < matrix.numberColumn; j++ {
			tempValue := big.NewInt(0)
			for k := uint64(0); k < m.numberColumn; k++ {
				tempValue.Add(tempValue, new(big.Int).Mul(m.matrix[i][k], matrix.matrix[k][j]))
			}
			tempSlice[j] = tempValue
		}
		m.matrix[i] = tempSlice
	}
	m.numberColumn = matrix.numberColumn
	return m, nil
}

// All components of a matrix modulus a fieldOrder.
// Ex: A = [10, 9]    and fieldOrder = 7
//         [23, 14]
// Then output is [3, 2]
//                [2, 0]
func (m *Matrix) modulus() *Matrix {
	for i := uint64(0); i < m.numberRow; i++ {
		for j := uint64(0); j < m.numberColumn; j++ {
			m.matrix[i][j].Mod(m.matrix[i][j], m.fieldOrder)
		}
	}
	return m
}

// Interchange two rows of a given matrix.
// Ex: A = [10, 9]    and fieldOrder = 7
//         [23, 14]
// SwapRow(A,0,1) = [23, 14]
//                  [10, 9]
func (m *Matrix) swapRow(nIndexRow1 uint64, nIndexRow2 uint64) (*Matrix, error) {
	if m.numberRow <= nIndexRow1 || m.numberRow <= nIndexRow2 {
		return nil, ErrOutOfRange
	}

	// Do nothing
	if nIndexRow1 == nIndexRow2 {
		return m, nil
	}
	for i := uint64(0); i < m.numberColumn; i++ {
		m.matrix[nIndexRow1][i], m.matrix[nIndexRow2][i] = m.matrix[nIndexRow2][i], m.matrix[nIndexRow1][i]
	}
	return m, nil
}

func (m *Matrix) swapColumn(nIndexColumn1 uint64, nIndexColumn2 uint64) (*Matrix, error) {
	if m.numberColumn <= nIndexColumn1 || m.numberColumn <= nIndexColumn2 {
		return nil, ErrOutOfRange
	}

	for i := uint64(0); i < m.numberRow; i++ {
		m.matrix[i][nIndexColumn1], m.matrix[i][nIndexColumn2] = m.matrix[i][nIndexColumn2], m.matrix[i][nIndexColumn1]
	}
	return m, nil
}

// IsSquare checks if this matrix is square or not
func (m *Matrix) IsSquare() bool {
	return m.numberColumn == m.numberRow
}

// Inverse gets the inverse matrix
func (m *Matrix) Inverse() (*Matrix, error) {
	if !m.IsSquare() {
		return nil, ErrNotSquareMatrix
	}
	// Get U, L^{-1}. Note that A= L*U
	upperMatrix, lowerMatrix, _, err := m.getGaussElimination()
	if err != nil {
		return nil, err
	}

	copyLowerMatrix := lowerMatrix.Copy()
	// K=U^t
	upperMatrix.Transpose()
	// Get D, L_K^{-1}. Note that K=L_K*D
	tempUpperResult, tempLowerResult, _, err := upperMatrix.getGaussElimination()
	if err != nil {
		return nil, err
	}
	tempResult, err := tempLowerResult.multiInverseDiagonal(tempUpperResult)
	if err != nil {
		return nil, err
	}
	// Get (D^{-1}L_{K}^{-1})^t = ((L_K*D)^{-1})^t = (K^{-1})^{t}, so the transpose of (K^{-1})^{t} is U^{-1}
	tempResult.Transpose()

	// U^{-1}*L^{-1} = (L*U)^{-1} = A^{-1}
	tempResult, err = tempResult.multiply(copyLowerMatrix)
	if err != nil {
		return nil, err
	}
	m = tempResult.modulus()
	return m, nil
}

// Determinant returns the determinant of the matrix
func (m *Matrix) Determinant() (*big.Int, error) {
	if !m.IsSquare() {
		return nil, ErrNotSquareMatrix
	}
	m.modulus()
	// We only use elementary matrix (i.e. its determine is 1), so det(upperMatrix)=det(A).
	// Furthermore, upperMatrix is a uppertriangular matrix. Thus, the determinant of this matrix
	// is the multiplication of all diagonal elements.
	upperMatrix, _, permutationTimes, err := m.getGaussElimination()
	if err != nil {
		return big.NewInt(0), nil
	}
	result := big.NewInt(1)
	for i := uint64(0); i < m.numberRow; i++ {
		result.Mul(result, upperMatrix.matrix[i][i])
		result.Mod(result, m.fieldOrder)
	}
	// negative result if the times of permutation is odd
	if permutationTimes%2 == 1 {
		result.Neg(result)
	}
	result.Mod(result, m.fieldOrder)
	return result, nil
}

// Only work "matrixA is squared-matrix"
// Then the output is U_A and L^{-1} such that LU_A = A. Here U_A is a upper triangular matrix
// with det(U_A) = det(A). (i.e. <A|I> = <U_A|L^{-1}> by Gauss elimination)
func (m *Matrix) getGaussElimination() (*Matrix, *Matrix, int, error) {
	if !m.IsSquare() {
		return nil, nil, 0, ErrNotSquareMatrix
	}
	lower, err := newIdentityMatrix(m.numberRow, m.fieldOrder)
	if err != nil {
		return nil, nil, 0, err
	}
	upper := m.Copy()
	permutationTimes := 0
	for i := uint64(0); i < m.numberRow; i++ {
		changeIndex, found := upper.getNonZeroCoefficientByRow(i, i)
		if !found {
			return nil, nil, 0, ErrNotInvertableMatrix
		}
		// If the index is changed, swap rows
		if i != changeIndex {
			permutationTimes++
			// Swap lower and higher matrix
			upper, err = upper.swapRow(i, changeIndex)
			if err != nil {
				return nil, nil, 0, err
			}
			lower, err = lower.swapRow(i, changeIndex)
			if err != nil {
				return nil, nil, 0, err
			}
		}
		inverse := upper.modInverse(i, i)
		if inverse == nil {
			return nil, nil, 0, ErrNotInvertableMatrix
		}
		for j := i + 1; j < m.numberRow; j++ {
			tempValue := new(big.Int).Mul(upper.matrix[j][i], inverse)
			inverseDiagonalComponent := new(big.Int).Neg(tempValue)
			// Make (j, i) element to zero at upper matrix
			rowI, err := upper.GetRow(i)
			if err != nil {
				return nil, nil, 0, err
			}
			rowJ, err := upper.GetRow(j)
			if err != nil {
				return nil, nil, 0, err
			}
			tempResultASlice := multiScalar(rowI, inverseDiagonalComponent)
			upper.matrix[j] = addSlices(rowJ, tempResultASlice)

			// Do the same above operation at lower matrix
			rowLowerI, err := lower.GetRow(i)
			if err != nil {
				return nil, nil, 0, err
			}
			rowLowerJ, err := lower.GetRow(j)
			if err != nil {
				return nil, nil, 0, err
			}
			tempResultIdentitySlice := multiScalar(rowLowerI, inverseDiagonalComponent)
			lower.matrix[j] = addSlices(rowLowerJ, tempResultIdentitySlice)
		}
	}
	upper = upper.modulus()
	lower = lower.modulus()
	return upper, lower, permutationTimes, nil
}

func (m *Matrix) getNonZeroCoefficientByRow(columnIdx uint64, fromRowIndex uint64) (uint64, bool) {
	for i := fromRowIndex; i < m.numberRow; i++ {
		if m.Get(i, columnIdx).Cmp(big0) != 0 {
			return i, true
		}
	}
	return 0, false
}

// GetMatrixRank returns the number of linearly independent column over finite field with order fieldOrder.
// As give the index of rows of a matrix, this function will find nonzero value such that this value has the smallest index of rows.
func (m *Matrix) GetMatrixRank(fieldOrder *big.Int) (uint64, error) {
	upper := m.Copy()
	if upper.numberRow < upper.numberColumn {
		upper = upper.Transpose()
	}
	rank := uint64(0)
	for i := uint64(0); i < upper.numberColumn; i++ {
		changeIndex, found := upper.getNonZeroCoefficientByRow(i, rank)
		// If the column are all zero, we skip the column.
		if !found {
			continue
		}
		// If the index is changed, swap rows
		if rank != changeIndex {
			var err error
			upper, err = upper.swapRow(rank, changeIndex)
			if err != nil {
				return 0, err
			}
		}
		inverse := upper.modInverse(rank, i)
		if inverse == nil {
			return 0, ErrNotInvertableMatrix
		}
		rowI, err := upper.GetRow(rank)
		if err != nil {
			return 0, err
		}
		for j := rank + 1; j < upper.numberRow; j++ {
			tempValue := new(big.Int).Mul(upper.matrix[j][i], inverse)
			inverseDiagonalComponent := new(big.Int).Neg(tempValue)
			rowJ, err := upper.GetRow(j)
			if err != nil {
				return 0, err
			}
			tempResultASlice := multiScalar(rowI, inverseDiagonalComponent)
			upper.matrix[j] = addSlices(rowJ, tempResultASlice)
		}
		upper = upper.modulus()
		rank++
	}
	return rank, nil
}

// multiInverseDiagonal inverse the diagonal matrix and multiplies it
// Only use in computing inverse matrix.
func (m *Matrix) multiInverseDiagonal(diagonal *Matrix) (*Matrix, error) {
	rank := m.numberRow
	for i := uint64(0); i < rank; i++ {
		inverse := diagonal.modInverse(i, i)
		if inverse == nil {
			return nil, ErrNotInvertableMatrix
		}
		for j := uint64(0); j < rank; j++ {
			m.matrix[i][j].Mul(m.matrix[i][j], inverse)
		}
	}
	return m, nil
}

// DeleteRow deletes the rows from nLowerIndex to nUpperIndex
// Ex:
// a_11 a_12 a_13 a_14
// a_21 a_22 a_23 a_24
// a_31 a_32 a_33 a_34
// a_41 a_42 a_43 a_44
// Then DeleteRow(1, 2) will gives
// a_11 a_12 a_13 a_14
// a_41 a_42 a_43 a_44
func (m *Matrix) DeleteRow(nLowerIndex, nUpperIndex uint64) (*Matrix, error) {
	if nUpperIndex >= m.numberRow {
		return nil, ErrOutOfRange
	}
	if nLowerIndex > nUpperIndex {
		return nil, ErrOutOfRange
	}

	var reduceMatrix [][]*big.Int
	for i := uint64(0); i < m.numberRow; i++ {
		if i >= nLowerIndex && i <= nUpperIndex {
			continue
		}
		reduceMatrix = append(reduceMatrix, m.matrix[i])
	}
	resultMatrix, err := NewMatrix(m.fieldOrder, reduceMatrix)
	if err != nil {
		return nil, err
	}
	return resultMatrix, nil
}

// DeleteColumn deletes the columns from nLowerIndex to nUpperIndex
// Ex:
// a_11 a_12 a_13 a_14
// a_21 a_22 a_23 a_24
// a_31 a_32 a_33 a_34
// a_41 a_42 a_43 a_44
// Then DeleteRow(1, 2) will gives
// a_11 a_14
// a_21 a_24
// a_31 a_34
// a_41 a_44
func (m *Matrix) DeleteColumn(nLowerIndex, nUpperIndex uint64) (*Matrix, error) {
	transposeM := m.Transpose()
	transposeM, err := transposeM.DeleteRow(nLowerIndex, nUpperIndex)
	if err != nil {
		return nil, err
	}
	return transposeM.Transpose(), nil
}

// Pseudoinverse is the general inverse of non-square matrix. This is a special case of Pseudoinverse. In particular,
// if the matrix is non-singular and square, then Pseudoinverse is the standard inverse matrix.
// More details can be found in https://en.wikipedia.org/wiki/Moore%E2%80%93Penrose_inverse
// If m^t*m is invertible. In this case, an explicitly formula is : (m^t*m)^(-1)*m^t.
// TODO: This function only works under the following conditions:
// - the columns of m are linearly independent
// - row rank >= column rank
func (m *Matrix) Pseudoinverse() (*Matrix, error) {
	copy := m.Copy()
	copyTranspose := m.Copy()
	copyTranspose.Transpose()
	copyTran := m.Copy()
	copyTran.Transpose()
	symmetricForm, err := copyTranspose.multiply(copy)
	if err != nil {
		return nil, err
	}
	// (m^t*m)^(-1)
	inverseSymmetric, err := symmetricForm.Inverse()
	if err != nil {
		return nil, err
	}
	// (m^t*m)^(-1)*m^t
	result, err := inverseSymmetric.multiply(copyTran)
	result.modulus()
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (m *Matrix) Equal(m2 *Matrix) bool {
	if m2 == m {
		return true
	}
	if m.numberRow != m2.numberRow {
		return false
	}
	if m.numberColumn != m2.numberColumn {
		return false
	}
	if m.fieldOrder.Cmp(m2.fieldOrder) != 0 {
		return false
	}
	for i, mm := range m.matrix {
		for j := range mm {
			if m.Get(uint64(i), uint64(j)).Cmp(m2.Get(uint64(i), uint64(j))) != 0 {
				return false
			}
		}
	}
	return true
}
