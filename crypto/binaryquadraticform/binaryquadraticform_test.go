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

package binaryquadraticform

import (
	"math/big"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("binary quadratic", func() {
	Context("IsReducedForm()", func() {
		It("failure", func() {
			// The output of NewBQuadraticForm is reduced. But in this test, we should give an example which is not reduced. So we set it in force.
			testbqForm, err := NewBQuadraticForm(big.NewInt(33), big.NewInt(11), big.NewInt(5))
			testbqForm.a = big.NewInt(33)
			testbqForm.b = big.NewInt(11)
			testbqForm.c = big.NewInt(5)
			Expect(err).Should(BeNil())
			got := testbqForm.IsReducedForm()
			Expect(got).Should(BeFalse())
		})
	})

	Context("NewBQuadraticFormByDiscriminant()", func() {
		It("This form does not exist 1", func() {
			got, err := NewBQuadraticForm(big.NewInt(0), big.NewInt(0), big.NewInt(5))
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ErrPositiveDiscriminant))
		})

		It("This form does not exist 2", func() {
			got, err := NewBQuadraticForm(big.NewInt(1), big.NewInt(10), big.NewInt(10))
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ErrPositiveDiscriminant))
		})
	})

	DescribeTable("Reduction()", func(inputa *big.Int, inputb *big.Int, inputc *big.Int, expecteda *big.Int, expectedb *big.Int, expectedc *big.Int) {
		input, err := NewBQuadraticForm(inputa, inputb, inputc)
		Expect(err).Should(BeNil())
		expected, err := NewBQuadraticForm(expecteda, expectedb, expectedc)
		Expect(err).Should(BeNil())
		Expect(input).Should(Equal(expected))
	},
		Entry("Input Form:(33,11,5); Expected Form:(5,-1,27)",
			big.NewInt(33), big.NewInt(11), big.NewInt(5),
			big.NewInt(5), big.NewInt(-1), big.NewInt(27),
		),
		Entry("Input Form:(15,0,15); Expected Form:(15,0,15)",
			big.NewInt(15), big.NewInt(0), big.NewInt(15),
			big.NewInt(15), big.NewInt(0), big.NewInt(15),
		),
		Entry("Input Form:(6,3,1); Expected Form:(1,1,4)",
			big.NewInt(6), big.NewInt(3), big.NewInt(1),
			big.NewInt(1), big.NewInt(1), big.NewInt(4),
		),
		Entry("Input Form:(1,2,3); Expected Form:(1,0,2)",
			big.NewInt(1), big.NewInt(2), big.NewInt(3),
			big.NewInt(1), big.NewInt(0), big.NewInt(2),
		),
		Entry("Input Form:(1,2,30); Expected Form:(1,0,29)",
			big.NewInt(1), big.NewInt(2), big.NewInt(30),
			big.NewInt(1), big.NewInt(0), big.NewInt(29),
		),
		Entry("Input Form:(4,5,3); Expected Form:(2,-1,3)",
			big.NewInt(4), big.NewInt(5), big.NewInt(3),
			big.NewInt(2), big.NewInt(-1), big.NewInt(3),
		),
	)

	DescribeTable("Composition()", func(input1a *big.Int, input1b *big.Int, input1c *big.Int, input2a *big.Int, input2b *big.Int, input2c *big.Int,
		expecteda *big.Int, expectedb *big.Int, expectedc *big.Int) {
		input1, err := NewBQuadraticForm(input1a, input1b, input1c)
		Expect(err).Should(BeNil())
		input2, err := NewBQuadraticForm(input2a, input2b, input2c)
		Expect(err).Should(BeNil())
		got, err := input1.Composition(input2)
		Expect(err).Should(BeNil())

		expected, err := NewBQuadraticForm(expecteda, expectedb, expectedc)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(expected))
	},
		Entry(" Input1 Form:(1,1,6); Input2 Form:(1,1,6); Expected Form:(1,1,6); root4th: 2",
			big.NewInt(1), big.NewInt(1), big.NewInt(6),
			big.NewInt(1), big.NewInt(1), big.NewInt(6),
			big.NewInt(1), big.NewInt(1), big.NewInt(6),
		),
		Entry(" Input1 Form:(2,-1,3); Input2 Form:(2,-1,3); Expected Form:(2,1,3); root4th: 2",
			big.NewInt(2), big.NewInt(-1), big.NewInt(3),
			big.NewInt(2), big.NewInt(-1), big.NewInt(3),
			big.NewInt(2), big.NewInt(1), big.NewInt(3),
		),
		Entry(" Input1 Form:(2,-1,3); Input2 Form:(2,1,3); Expected Form:(1,1,6); root4th: 2",
			big.NewInt(2), big.NewInt(-1), big.NewInt(3),
			big.NewInt(2), big.NewInt(1), big.NewInt(3),
			big.NewInt(1), big.NewInt(1), big.NewInt(6),
		),
		Entry(" Input1 Form:(31,24,15951); Input2 Form:(31,24,15951); Expected Form:(517,100,961); root4th: 26",
			big.NewInt(31), big.NewInt(24), big.NewInt(15951),
			big.NewInt(31), big.NewInt(24), big.NewInt(15951),
			big.NewInt(517), big.NewInt(100), big.NewInt(961),
		),
		Entry(" Input1 Form:(142,130,3511); Input2 Form:(677,664,893); Expected Form:(591,564,971); root4th: 26",
			big.NewInt(142), big.NewInt(130), big.NewInt(3511),
			big.NewInt(677), big.NewInt(664), big.NewInt(893),
			big.NewInt(591), big.NewInt(564), big.NewInt(971),
		),
	)

	DescribeTable("square()", func(inputa *big.Int, inputb *big.Int, inputc *big.Int, expecteda *big.Int, expectedb *big.Int, expectedc *big.Int) {
		input, err := NewBQuadraticForm(inputa, inputb, inputc)
		Expect(err).Should(BeNil())
		got, err := input.square()
		Expect(err).Should(BeNil())

		expected, err := NewBQuadraticForm(expecteda, expectedb, expectedc)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(expected))
	},
		Entry("Input Form:(1,1,6); Expected Form:(1,1,6); root4th: 2",
			big.NewInt(1), big.NewInt(1), big.NewInt(6),
			big.NewInt(1), big.NewInt(1), big.NewInt(6),
		),
		Entry("Input Form:(19,18,26022); Expected Form:(361,-286,1426); root4th: 26",
			big.NewInt(19), big.NewInt(18), big.NewInt(26022),
			big.NewInt(361), big.NewInt(-286), big.NewInt(1426),
		),
		Entry("Input Form:(19,-12,262); Expected Form:(46,-32,113); root4th: 11",
			big.NewInt(19), big.NewInt(-12), big.NewInt(262),
			big.NewInt(46), big.NewInt(-32), big.NewInt(113),
		),
		Entry("Input Form:(31,24,15951); Expected Form:(517,100,961); root4th: 26",
			big.NewInt(31), big.NewInt(24), big.NewInt(15951),
			big.NewInt(517), big.NewInt(100), big.NewInt(961),
		),
		Entry("Input Form:(517,100,961); Expected Form:(529,-378,1002); root4th: 26",
			big.NewInt(517), big.NewInt(100), big.NewInt(961),
			big.NewInt(529), big.NewInt(-378), big.NewInt(1002),
		),
		Entry("Input Form:(3,-2,176081); Expected Form:(9,4,58694); root4th: 19",
			big.NewInt(3), big.NewInt(-2), big.NewInt(176081),
			big.NewInt(9), big.NewInt(4), big.NewInt(58694),
		),
		Entry("Input Form:(729,626,859); Expected Form:(419,-412,1362); root4th: 26",
			big.NewInt(729), big.NewInt(626), big.NewInt(859),
			big.NewInt(419), big.NewInt(-412), big.NewInt(1362),
		),
	)

	DescribeTable("cube()", func(inputa *big.Int, inputb *big.Int, inputc *big.Int, expecteda *big.Int, expectedb *big.Int, expectedc *big.Int) {
		input, err := NewBQuadraticForm(inputa, inputb, inputc)
		Expect(err).Should(BeNil())
		got, err := input.cube()
		Expect(err).Should(BeNil())

		expected, err := NewBQuadraticForm(expecteda, expectedb, expectedc)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(expected))
	},
		Entry("Input Form:(31,24,15951); Expected Form:(286,54,1731); root4th: 26",
			big.NewInt(31), big.NewInt(24), big.NewInt(15951),
			big.NewInt(286), big.NewInt(54), big.NewInt(1731),
		),
		Entry("Input Form:(19,18,26022); Expected Form:(79,38,6262); root4th: 26",
			big.NewInt(19), big.NewInt(18), big.NewInt(26022),
			big.NewInt(79), big.NewInt(38), big.NewInt(6262),
		),
		Entry("Input Form:(22,6,225); Expected Form:(70,54,81); root4th: 11",
			big.NewInt(22), big.NewInt(6), big.NewInt(225),
			big.NewInt(70), big.NewInt(54), big.NewInt(81),
		),
		Entry("Input Form:(19,-12,262); Expected Form:(61,22,83), root4th: 8",
			big.NewInt(19), big.NewInt(-12), big.NewInt(262),
			big.NewInt(61), big.NewInt(22), big.NewInt(83),
		),
		Entry("Input Form:(3,-2,176081); Expected Form:(27,22,19569); root4th: 19",
			big.NewInt(3), big.NewInt(-2), big.NewInt(176081),
			big.NewInt(27), big.NewInt(22), big.NewInt(19569),
		),
	)

	DescribeTable("Exp()", func(inputa *big.Int, inputb *big.Int, inputc *big.Int, expecteda *big.Int, expectedb *big.Int, expectedc, exp *big.Int) {
		input, err := NewBQuadraticForm(inputa, inputb, inputc)
		Expect(err).Should(BeNil())
		got, err := input.Exp(exp)
		Expect(err).Should(BeNil())

		expected, err := NewBQuadraticForm(expecteda, expectedb, expectedc)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(expected))
	},
		Entry("Input Form:(2,1,3); Expected Form:(1,1,6); root4th: 26; exp: 6",
			big.NewInt(2), big.NewInt(1), big.NewInt(3),
			big.NewInt(1), big.NewInt(1), big.NewInt(6),
			big.NewInt(6),
		),
		Entry("Input Form:(31,24,15951); Expected Form:(517,-276,993); root4th: 26; exp: 200",
			big.NewInt(31), big.NewInt(24), big.NewInt(15951),
			big.NewInt(517), big.NewInt(-276), big.NewInt(993),
			big.NewInt(200),
		),
		Entry("Input Form:(78,-52,6781); Expected Form:(738,-608,841); root4th: 26; exp: 500",
			big.NewInt(78), big.NewInt(-52), big.NewInt(6781),
			big.NewInt(738), big.NewInt(-608), big.NewInt(841),
			big.NewInt(500),
		),
		Entry("Input Form:(101,38,4898); Expected Form:(61,54,7501); root4th: 26; exp: 508",
			big.NewInt(101), big.NewInt(38), big.NewInt(4898),
			big.NewInt(66), big.NewInt(54), big.NewInt(7501),
			big.NewInt(508),
		),
		Entry("Input Form:(101,38,4898); Expected Form:(101,38,4898); root4th: 26; exp: 1",
			big.NewInt(101), big.NewInt(38), big.NewInt(4898),
			big.NewInt(101), big.NewInt(38), big.NewInt(4898),
			big.NewInt(1),
		),
		Entry("Input Form:(101,38,4898); Expected Form:(101,38,4898); root4th: 26; exp: 22999971",
			big.NewInt(101), big.NewInt(38), big.NewInt(4898),
			big.NewInt(101), big.NewInt(38), big.NewInt(4898),
			big.NewInt(22999971),
		),
	)

	Context("Exp()", func() {
		It("Neg power", func() {
			bq, err := NewBQuadraticForm(big.NewInt(101), big.NewInt(38), big.NewInt(4898))
			positivePower := big.NewInt(10)
			negPower := big.NewInt(-10)
			bqPositive, err := bq.Exp(positivePower)
			Expect(err).Should(BeNil())
			bqNegtive, err := bq.Exp(negPower)
			Expect(err).Should(BeNil())
			got, err := bqPositive.Composition(bqNegtive)
			Expect(err).Should(BeNil())
			expected := bq.Identity()
			Expect(got).Should(Equal(expected))
		})
	})

	Context("Get()", func() {
		It("Geta", func() {
			a := big.NewInt(101)
			b := big.NewInt(38)
			c := big.NewInt(4898)
			testbqForm, err := NewBQuadraticForm(a, b, c)
			Expect(err).Should(BeNil())
			got := testbqForm.GetA()
			Expect(got.Cmp(a) == 0).Should(BeTrue())
		})
		It("Getb", func() {
			a := big.NewInt(101)
			b := big.NewInt(38)
			c := big.NewInt(4898)
			testbqForm, err := NewBQuadraticForm(a, b, c)
			Expect(err).Should(BeNil())
			got := testbqForm.GetB()
			Expect(got.Cmp(b) == 0).Should(BeTrue())
		})
		It("Getc", func() {
			a := big.NewInt(101)
			b := big.NewInt(38)
			c := big.NewInt(4898)
			testbqForm, err := NewBQuadraticForm(a, b, c)
			Expect(err).Should(BeNil())
			got := testbqForm.GetC()
			Expect(got.Cmp(c) == 0).Should(BeTrue())
		})
		It("Getdiscriminant()", func() {
			a := big.NewInt(101)
			b := big.NewInt(38)
			c := big.NewInt(4898)
			testbqForm, err := NewBQuadraticForm(a, b, c)
			Expect(err).Should(BeNil())
			got, err := computeDiscriminant(a, b, c)
			Expect(err).Should(BeNil())
			Expect(got.Cmp(testbqForm.GetDiscriminant()) == 0).Should(BeTrue())
		})
	})
})

func TestBinaryquadraticform(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Binaryquadraticform Suite")
}
