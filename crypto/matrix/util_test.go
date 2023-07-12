// Copyright © 2020 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package matrix

import (
	"math/big"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Util test", func() {
	Context("IdentityMatrix()", func() {
		DescribeTable("should be ok", func(rank uint64) {
			m, err := newIdentityMatrix(rank, fieldOrder)
			Expect(err).Should(BeNil())
			Expect(m.fieldOrder).Should(Equal(fieldOrder))
			Expect(m.GetNumberColumn()).Should(Equal(rank))
		},
			Entry("minimun rank", uint64(1)),
			Entry("minimun rank", uint64(50)),
		)

		It("zero rank", func() {
			m, err := newIdentityMatrix(0, fieldOrder)
			Expect(err).Should(Equal(ErrZeroOrNegativeRank))
			Expect(m).Should(BeNil())
		})

		It("nil field order", func() {
			m, err := newIdentityMatrix(1, nil)
			Expect(err).Should(Equal(ErrNonPrimeFieldOrder))
			Expect(m).Should(BeNil())
		})

		It("zero field order", func() {
			m, err := newIdentityMatrix(1, big.NewInt(0))
			Expect(err).Should(Equal(ErrNonPrimeFieldOrder))
			Expect(m).Should(BeNil())
		})
	})

	DescribeTable("multiScalar()", func(slice []*big.Int, scalar *big.Int) {
		m := multiScalar(slice, scalar)
		Expect(m).Should(HaveLen(len(slice)))
		for i, v := range m {
			Expect(v).Should(Equal(new(big.Int).Mul(slice[i], scalar)))
		}
	},
		Entry("nil slice", nil, big.NewInt(1)),
		Entry("normal case", []*big.Int{
			big.NewInt(1),
			big.NewInt(2),
			big.NewInt(3),
		}, big.NewInt(2)))

	DescribeTable("addSlices()", func(sliceA []*big.Int, sliceB []*big.Int) {
		m := addSlices(sliceA, sliceB)
		Expect(m).Should(HaveLen(len(sliceA)))
		for i, v := range m {
			Expect(v).Should(Equal(new(big.Int).Add(sliceA[i], sliceB[i])))
		}
	},
		Entry("normal case", []*big.Int{
			big.NewInt(1),
			big.NewInt(2),
			big.NewInt(3),
		}, []*big.Int{
			big.NewInt(4),
			big.NewInt(5),
			big.NewInt(6),
		}))
})

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Matrix Test")
}
