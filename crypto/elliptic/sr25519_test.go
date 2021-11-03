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
package elliptic

import (
	"math/big"

	"github.com/gtank/ristretto255"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var (
	sr25519 = NewSR25519()
)

var _ = Describe("sr25519", func() {
	DescribeTable("ScalarBaseMult", func(inputValue *big.Int) {
		scalar, err := ristretto255.NewScalar().SetCanonicalBytes(reverse(inputValue.FillBytes(make([]byte, 32))))
		Expect(err).Should(BeNil())
		pt1 := ristretto255.NewElement().ScalarBaseMult(scalar)
		gotX, gotY := pt1.ToAffineCoordinate()
		expectedX, expectedY := sr25519.ScalarBaseMult(inputValue.Bytes())
		Expect(gotX.Cmp(expectedX) == 0).Should(BeTrue())
		Expect(gotY.Cmp(expectedY) == 0).Should(BeTrue())
	},
		Entry("Case1", big.NewInt(101)),
		Entry("Cas32", big.NewInt(2384792749)),
	)

	DescribeTable("ScalarMult", func(inputValue *big.Int, baseScalarValue *big.Int) {
		baseScalar, err := ristretto255.NewScalar().SetCanonicalBytes(reverse(baseScalarValue.FillBytes(make([]byte, 32))))
		Expect(err).Should(BeNil())
		scalar, err := ristretto255.NewScalar().SetCanonicalBytes(reverse(inputValue.FillBytes(make([]byte, 32))))
		Expect(err).Should(BeNil())
		pt := ristretto255.NewElement().ScalarBaseMult(baseScalar)
		pt1 := ristretto255.NewElement().ScalarMult(scalar, pt)
		gotX, gotY := pt1.ToAffineCoordinate()

		expectedX, expectedY := sr25519.ScalarBaseMult(baseScalarValue.Bytes())
		expectedX, expectedY = sr25519.ScalarMult(expectedX, expectedY, inputValue.Bytes())
		Expect(gotX.Cmp(expectedX) == 0).Should(BeTrue())
		Expect(gotY.Cmp(expectedY) == 0).Should(BeTrue())
	},
		Entry("Case1", big.NewInt(101), big.NewInt(8077818)),
		Entry("Cas32", big.NewInt(2384792749), big.NewInt(8077616)),
	)

	DescribeTable("ScalarMul", func(input1 *big.Int, input2 *big.Int) {
		scalar1, err := ristretto255.NewScalar().SetCanonicalBytes(reverse(input1.FillBytes(make([]byte, 32))))
		Expect(err).Should(BeNil())
		scalar2, err := ristretto255.NewScalar().SetCanonicalBytes(reverse(input2.FillBytes(make([]byte, 32))))
		Expect(err).Should(BeNil())
		pt1 := ristretto255.NewElement().ScalarBaseMult(scalar1)
		pt2 := ristretto255.NewElement().ScalarBaseMult(scalar2)
		gotX, gotY := ristretto255.NewElement().Add(pt1, pt2).ToAffineCoordinate()
		expectedX, expectedY := sr25519.ScalarBaseMult(new(big.Int).Add(input1, input2).Bytes())
		Expect(gotX.Cmp(expectedX) == 0).Should(BeTrue())
		Expect(gotY.Cmp(expectedY) == 0).Should(BeTrue())
	},
		Entry("Case1", big.NewInt(102341), big.NewInt(5102342)),
		Entry("Case2", big.NewInt(2384792749), big.NewInt(13441)),
	)

	Context("Negative Point", func() {
		It("It is OK", func() {
			value := big.NewInt(27364)
			negativeValue := new(big.Int).Sub(sr25519.Parameter.N, value)
			scalar, err := ristretto255.NewScalar().SetCanonicalBytes(reverse(negativeValue.FillBytes(make([]byte, 32))))
			Expect(err).Should(BeNil())
			pt1 := ristretto255.NewElement().ScalarBaseMult(scalar)
			gotX, gotY := pt1.ToAffineCoordinate()
			expectedX, expectedY := sr25519.ScalarBaseMult(value.Bytes())
			expectedX, expectedY = sr25519.Neg(expectedX, expectedY)
			Expect(gotX.Cmp(expectedX) == 0).Should(BeTrue())
			Expect(gotY.Cmp(expectedY) == 0).Should(BeTrue())
		})
	})

	It("Equal: two torsion", func() {
		negativeOne := new(big.Int).Mod(big.NewInt(-1), sr25519.Parameter.P)
		twoTorsionpt, err := ristretto255.ToExtendedProjectveCoordinate(big0, negativeOne)
		Expect(err).Should(BeNil())

		input := big.NewInt(23425)
		scalar, _ := ristretto255.NewScalar().SetCanonicalBytes(reverse(input.FillBytes(make([]byte, 32))))
		expected := ristretto255.NewElement().ScalarBaseMult(scalar)

		got := ristretto255.NewElement().Add(expected, twoTorsionpt)
		Expect(got.Equal(expected) == 1).Should(BeTrue())
	})
})

func reverse(input []byte) []byte {
	result := make([]byte, len(input))
	for i := 0; i < len(result); i++ {
		result[i] = input[31-i]
	}
	return result
}
