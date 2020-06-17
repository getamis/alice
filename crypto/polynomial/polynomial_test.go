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
package polynomial

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPolynomial(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Polynomial Suite")
}

var _ = Describe("Polynomial", func() {
	var (
		p            *Polynomial
		coefficients = []*big.Int{big.NewInt(1), big.NewInt(5), big.NewInt(2), big.NewInt(3)}
		bigNumber    = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
		bigPrime, _  = new(big.Int).SetString(bigNumber, 10)
	)

	BeforeEach(func() {
		var err error
		p, err = NewPolynomial(bigPrime, coefficients)
		Expect(err).Should(BeNil())
	})

	Context("RandomPolynomial", func() {
		It("should be ok", func() {
			p, err := RandomPolynomial(bigPrime, 3)
			Expect(err).Should(BeNil())
			Expect(p).ShouldNot(BeNil())
		})
	})

	Context("NewPolynomial", func() {
		It("invalid field order", func() {
			p, err := NewPolynomial(big.NewInt(2), coefficients)
			Expect(err).Should(Equal(utils.ErrLessOrEqualBig2))
			Expect(p).Should(BeNil())
		})
		It("empty coefficients", func() {
			p, err := NewPolynomial(bigPrime, []*big.Int{})
			Expect(err).Should(Equal(ErrEmptyCoefficients))
			Expect(p).Should(BeNil())
		})
	})

	Context("Differentiate()", func() {
		It("should be ok", func() {
			result := p.Differentiate(2)
			expected := []*big.Int{big.NewInt(4), big.NewInt(18)}
			Expect(result.coefficients).Should(Equal(expected))
		})

		It("return 0 if the times is over the the length of coefficients", func() {
			result := p.Differentiate(4)
			expected := []*big.Int{big.NewInt(0)}
			Expect(result.coefficients).Should(Equal(expected))
		})
	})

	Context("Evaluate()", func() {
		It("should be ok", func() {
			result := p.Evaluate(big.NewInt(2))
			Expect(result).Should(Equal(big.NewInt(43)))
		})

		It("return coefficients[0] if x == 0", func() {
			result := p.Evaluate(big.NewInt(0))
			Expect(result).Should(Equal(big.NewInt(1)))
		})
	})

	Context("Get()", func() {
		It("should be ok", func() {
			result := p.Get(2)
			Expect(result).Should(Equal(big.NewInt(2)))
		})

		It("return nil if the index is out of range", func() {
			result := p.Get(4)
			Expect(result).Should(BeNil())
		})
	})

	Context("Len() & Degree()", func() {
		It("len = degree + 1", func() {
			Expect(p.Len()).Should(BeNumerically("==", 4))
			Expect(p.Degree()).Should(BeNumerically("==", p.Len()-1))
		})
	})

	Context("SetConstant()", func() {
		It("should be ok", func() {
			p.SetConstant(big.NewInt(6))
			Expect(p.coefficients[0]).Should(Equal(big.NewInt(6)))
		})
	})

	Context("Max()", func() {
		It("should be ok", func() {
			Expect(Max(48, 28)).Should(Equal(48))
		})
	})

	Context("Add()", func() {
		It("should be ok", func() {
			p1coe := []*big.Int{big.NewInt(1), big.NewInt(5), big.NewInt(2), big.NewInt(3)}
			p2coe := []*big.Int{big.NewInt(3), big.NewInt(15), big.NewInt(2), big.NewInt(3)}
			p1, err := NewPolynomial(bigPrime, p1coe)
			Expect(err).Should(BeNil())
			p2, err := NewPolynomial(bigPrime, p2coe)
			Expect(err).Should(BeNil())
			result := p1.Add(p2)
			solutionCoe := []*big.Int{big.NewInt(4), big.NewInt(20), big.NewInt(4), big.NewInt(6)}

			Expect(result.coefficients).Should(Equal(solutionCoe))
		})
	})
})
