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

	"github.com/getamis/alice/crypto/matrix"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("group config test", func() {
	DescribeTable("andMatrix()", func(m1 [][]*big.Int, m2 [][]*big.Int, exptected [][]*big.Int) {
		M1, err := matrix.NewMatrix(nil, m1)
		Expect(err).Should(BeNil())
		M2, err := matrix.NewMatrix(nil, m2)
		Expect(err).Should(BeNil())
		E, err := matrix.NewMatrix(nil, exptected)
		Expect(err).Should(BeNil())
		got, err := andMatrix(M1, M2)
		Expect(err).Should(BeNil())
		Expect(got.Equal(E)).Should(BeTrue())
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
		M2, err := matrix.NewMatrix(nil, m2)
		Expect(err).Should(BeNil())
		E, err := matrix.NewMatrix(nil, exptected)
		Expect(err).Should(BeNil())
		got, err := orMatrix(M1, M2)
		Expect(err).Should(BeNil())
		Expect(got.Equal(E)).Should(BeTrue())
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
		Expect(got).Should(Equal(e))
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
