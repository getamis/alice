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
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sparse matrix", func() {
	DescribeTable("ToCSR()", func(matrix [][]*big.Int, expectedValue []*big.Int, expectedColumnIdx []uint64, expectedRowIdx []uint64, order *big.Int) {
		m, err := NewMatrix(order, matrix)
		Expect(err).Should(BeNil())
		c := m.ToCSR()
		Expect(c.value).Should(Equal(expectedValue))
		Expect(c.columnIdx).Should(Equal(expectedColumnIdx))
		Expect(c.rowIdx).Should(Equal(expectedRowIdx))
	},
		Entry("normal case: finite field", [][]*big.Int{
			{big.NewInt(0), big.NewInt(0), big.NewInt(19)},
			{big.NewInt(0), big.NewInt(74), big.NewInt(0)},
			{big.NewInt(3), big.NewInt(0), big.NewInt(15)},
		}, []*big.Int{
			big.NewInt(19), big.NewInt(74), big.NewInt(3), big.NewInt(15),
		}, []uint64{2, 1, 0, 2}, []uint64{0, 1, 2, 4}, fieldOrder),

		// Example : https://en.wikipedia.org/wiki/Sparse_matrix
		Entry("normal case: over Z", [][]*big.Int{
			{big.NewInt(10), big.NewInt(20), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(30), big.NewInt(0), big.NewInt(40), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(50), big.NewInt(60), big.NewInt(70), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(80)},
		}, []*big.Int{
			big.NewInt(10), big.NewInt(20), big.NewInt(30), big.NewInt(40), big.NewInt(50), big.NewInt(60), big.NewInt(70), big.NewInt(80),
		}, []uint64{0, 1, 1, 3, 2, 3, 4, 5}, []uint64{0, 2, 4, 7, 8}, nil),
	)

	DescribeTable("MultiplyVector()", func(matrix [][]*big.Int, vector [][]*big.Int, order *big.Int) {
		m, err := NewMatrix(order, matrix)
		Expect(err).Should(BeNil())
		c := m.ToCSR()
		vecMatrix, err := NewMatrix(m.fieldOrder, vector)
		Expect(err).Should(BeNil())
		got, err := c.MultiplyVector(vecMatrix)
		Expect(err).Should(BeNil())
		expect, err := m.Multiply(vecMatrix)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(expect))
	},
		Entry("normal case: finite field", [][]*big.Int{
			{big.NewInt(0), big.NewInt(0), big.NewInt(19)},
			{big.NewInt(0), big.NewInt(74), big.NewInt(0)},
			{big.NewInt(3), big.NewInt(0), big.NewInt(15)},
		}, [][]*big.Int{
			{big.NewInt(5)},
			{big.NewInt(2)},
			{big.NewInt(3)},
		}, fieldOrder),

		Entry("normal case: over Z", [][]*big.Int{
			{big.NewInt(10), big.NewInt(20), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(30), big.NewInt(0), big.NewInt(40), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(50), big.NewInt(60), big.NewInt(70), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(80)},
		}, [][]*big.Int{
			{big.NewInt(5)},
			{big.NewInt(2)},
			{big.NewInt(3)},
			{big.NewInt(1)},
			{big.NewInt(20)},
			{big.NewInt(53)},
		}, nil),
	)

	It("MultiplyVector: not vector", func() {
		m, err := newIdentityMatrix(1, fieldOrder)
		vector, err := newIdentityMatrix(2, fieldOrder)
		c := m.ToCSR()
		got, err := c.MultiplyVector(vector)
		Expect(err).Should(Equal(ErrNotVector))
		Expect(got).Should(BeNil())
	})
})
