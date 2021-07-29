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
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/matrix"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("group config test", func() {
	DescribeTable("andMatrix()", func(m1 [][]*big.Int, m2 [][]*big.Int, exptected [][]*big.Int) {
		M1, err := matrix.NewMatrix(nil, m1)
		Expect(err).Should(BeNil())
		m1CSR := M1.ToCSR()
		M2, err := matrix.NewMatrix(nil, m2)
		Expect(err).Should(BeNil())
		m2CSR := M2.ToCSR()
		E, err := matrix.NewMatrix(nil, exptected)
		Expect(err).Should(BeNil())
		got := andMatrixCSR(m1CSR, m2CSR)
		Expect(err).Should(BeNil())
		Ecsr := E.ToCSR()
		Expect(got).Should(Equal(Ecsr))
	},
		Entry("normal case", [][]*big.Int{
			{big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1)},
		}),
		Entry("normal case", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		}),
		Entry("normal case", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
		}),
		Entry("normal case", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		}),
	)

	DescribeTable("orMatrix()", func(m1 [][]*big.Int, m2 [][]*big.Int, exptected [][]*big.Int) {
		M1, err := matrix.NewMatrix(nil, m1)
		Expect(err).Should(BeNil())
		m1CSR := M1.ToCSR()
		M2, err := matrix.NewMatrix(nil, m2)
		Expect(err).Should(BeNil())
		m2CSR := M2.ToCSR()
		E, err := matrix.NewMatrix(nil, exptected)
		Expect(err).Should(BeNil())
		got := orMatrixCSR(m1CSR, m2CSR)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(E.ToCSR()))
	},
		Entry("normal case", [][]*big.Int{
			{big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1)},
			{big.NewInt(1)},
		}),
		Entry("normal case", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1)},
			{big.NewInt(1), big.NewInt(0)},
		}),
		Entry("normal case", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
		}),
		Entry("normal case", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(1), big.NewInt(0), big.NewInt(1), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		}),
	)

	DescribeTable("GenerateShare()", func(threshold int, totalParticipant int, exptected [][]*big.Int) {
		group, err := NewGroup(totalParticipant, threshold)
		Expect(err).Should(BeNil())
		got, err := group.GenerateMatrix()
		Expect(err).Should(BeNil())
		e, err := matrix.NewMatrix(nil, exptected)
		Expect(got).Should(Equal(e.ToCSR()))
		Expect(err).Should(BeNil())
	},
		Entry("normal case", 2, 3, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(1), big.NewInt(0), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
		}),
	)
})

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

func TestLiss(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Liss Test")
}
