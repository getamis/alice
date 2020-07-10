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
		p *Polynomial

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
		It("when err != nil", func() {
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

	Context("RemoveZeros()", func() {
		It("should be ok", func() {
			fieldOrder := big.NewInt(6)
			pcoe := []*big.Int{big.NewInt(1), big.NewInt(5), big.NewInt(2), big.NewInt(3), big0, big0, big0}
			p := &Polynomial{
				fieldOrder:   fieldOrder,
				coefficients: pcoe,
			}
			pRemoved := p.RemoveZeros()
			pSolution := []*big.Int{big.NewInt(1), big.NewInt(5), big.NewInt(2), big.NewInt(3)}
			Expect(pRemoved.coefficients).Should(Equal(pSolution))
		})
		It("when ends with nils", func() {
			fieldOrder := big.NewInt(7)
			pcoe := []*big.Int{big.NewInt(1), nil, nil, nil, nil, nil}
			p := &Polynomial{
				fieldOrder:   fieldOrder,
				coefficients: pcoe,
			}
			pRemoved := p.RemoveZeros()
			pSolution := []*big.Int{big.NewInt(1)}
			Expect(pRemoved.coefficients).Should(Equal(pSolution))
		})
		It("should remain 0 for constant term when all coeffcients are 0", func() {
			fieldOrder := big.NewInt(7)
			pcoe := []*big.Int{big.NewInt(0), nil, nil, nil}
			p := &Polynomial{
				fieldOrder:   fieldOrder,
				coefficients: pcoe,
			}
			pRemoved := p.RemoveZeros()
			pSolution := []*big.Int{big.NewInt(0)}
			Expect(pRemoved.coefficients).Should(Equal(pSolution))
		})
	})

	Context("Mod()", func() {
		It("should be ok", func() {
			fieldOrder := big.NewInt(6)
			pcoe := []*big.Int{big.NewInt(15), big.NewInt(51), big.NewInt(2), big.NewInt(6), big.NewInt(0), big.NewInt(7), big.NewInt(10)}
			p := &Polynomial{
				fieldOrder:   fieldOrder,
				coefficients: pcoe,
			}
			p.Mod()
			pSolution := []*big.Int{big.NewInt(3), big.NewInt(3), big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(4)}
			Expect(p.coefficients).Should(Equal(pSolution))
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
			sum := p1.Add(p2)
			solutionCoe := []*big.Int{big.NewInt(4), big.NewInt(20), big.NewInt(4), big.NewInt(6)}

			Expect(sum.coefficients).Should(Equal(solutionCoe))
		})
	})
	Context("Minus()", func() {
		It("poly with equal length", func() {
			fieldOrder := big.NewInt(10)
			p1coe := []*big.Int{big.NewInt(11), big.NewInt(50), big.NewInt(23), big.NewInt(31)}
			p2coe := []*big.Int{big.NewInt(3), big.NewInt(13), big.NewInt(21), big.NewInt(13)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			p2, err := NewPolynomial(fieldOrder, p2coe)
			Expect(err).Should(BeNil())
			difference := p1.Minus(p2)
			solutionCoe := []*big.Int{big.NewInt(8), big.NewInt(7), big.NewInt(2), big.NewInt(8)}
			Expect(difference.coefficients).Should(Equal(solutionCoe))
		})
		It("when subtracted poly has greater length", func() {
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big.NewInt(2)}
			p2coe := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			p2, err := NewPolynomial(fieldOrder, p2coe)
			Expect(err).Should(BeNil())
			difference := p1.Minus(p2)
			solutionCoe := []*big.Int{big.NewInt(1), big.NewInt(5), big.NewInt(4)}
			Expect(difference.coefficients).Should(Equal(solutionCoe))
		})
		It("when subtracted poly has shorter length", func() {
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
			p2coe := []*big.Int{big.NewInt(2)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			p2, err := NewPolynomial(fieldOrder, p2coe)
			Expect(err).Should(BeNil())
			difference := p1.Minus(p2)
			solutionCoe := []*big.Int{big.NewInt(6), big.NewInt(2), big.NewInt(3)}
			Expect(difference.coefficients).Should(Equal(solutionCoe))
		})
	})

	Context("Mul()", func() {
		It("should be ok", func() {
			fieldOrder := big.NewInt(10)
			p1coe := []*big.Int{big.NewInt(1), big.NewInt(5), big.NewInt(2)}
			p2coe := []*big.Int{big.NewInt(3), big.NewInt(13), big.NewInt(4)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			p2, err := NewPolynomial(fieldOrder, p2coe)
			Expect(err).Should(BeNil())
			product := p1.Mul(p2)
			solutionCoe := []*big.Int{big.NewInt(3), big.NewInt(8), big.NewInt(5), big.NewInt(6), big.NewInt(8)}
			Expect(product.coefficients).Should(Equal(solutionCoe))
		})
		It("when ends with nils", func() {
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big.NewInt(1), nil, nil, nil, nil, nil}
			p2coe := []*big.Int{big.NewInt(2), nil, nil, nil, nil, nil}
			p1 := &Polynomial{
				fieldOrder:   fieldOrder,
				coefficients: p1coe,
			}
			p1 = p1.RemoveZeros()
			p2 := &Polynomial{
				fieldOrder:   fieldOrder,
				coefficients: p2coe,
			}
			p2 = p2.RemoveZeros()
			product := p1.Mul(p2)
			solutionCoe := []*big.Int{big.NewInt(2)}
			Expect(product.coefficients).Should(Equal(solutionCoe))
		})
	})

	Context("rem()", func() {
		It("should be ok", func() {
			l := 4
			fieldOrder := big.NewInt(6)
			p1coe := []*big.Int{big.NewInt(7), big.NewInt(5), big.NewInt(6), big0, big.NewInt(4), big.NewInt(5)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			solutionCoe := []*big.Int{big.NewInt(1), big.NewInt(5)}
			soluP, err := NewPolynomial(fieldOrder, solutionCoe)
			Expect(p1.rem(l)).Should(Equal(soluP))
		})
	})

	Context("invert()", func() {
		It("should be ok", func() {
			l := big.NewInt(4)
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			solutionCoe := []*big.Int{big.NewInt(1), big.NewInt(5), big.NewInt(1), big.NewInt(4)}
			soluP, err := NewPolynomial(fieldOrder, solutionCoe)
			Expect(p1.invert(l)).Should(Equal(soluP))
		})
	})

	Context("rev()", func() {
		It("should be ok", func() {
			var k uint32 = 5
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big0, big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			solutionCoe := []*big.Int{big.NewInt(5), big.NewInt(4), big.NewInt(3), big.NewInt(2), big.NewInt(1)}
			soluP, err := NewPolynomial(fieldOrder, solutionCoe)
			Expect(p1.rev(k)).Should(Equal(soluP))
		})
		It("when degree of p is greater than k", func() {
			var k uint32 = 4
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big0, big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			Expect(p1.rev(k)).Should(BeNil())
		})
	})

	Context("CheckIfOnlyZero()", func() {
		It("should be ok", func() {
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big0, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			Expect(p1.CheckIfOnlyZero()).Should(Equal(true))
		})
		It("should be ok", func() {
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big0, big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			Expect(p1.CheckIfOnlyZero()).Should(Equal(false))
		})
	})

	Context("FDiv()", func() {
		It("should be ok", func() {
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}
			p2coe := []*big.Int{big.NewInt(3), big.NewInt(2), big.NewInt(1)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			p2, err := NewPolynomial(fieldOrder, p2coe)
			Expect(err).Should(BeNil())
			quotient, remainder, err := p1.FDiv(p2)
			Expect(err).Should(BeNil())
			solutionQuo := []*big.Int{big.NewInt(6), big.NewInt(0), big.NewInt(1), big.NewInt(5)}
			solutionRem := []*big.Int{big.NewInt(3), big.NewInt(3)}
			Expect(quotient.coefficients).Should(Equal(solutionQuo))
			Expect(remainder.coefficients).Should(Equal(solutionRem))
		})
		It("divisor has larger degree", func() {
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big.NewInt(3), big.NewInt(2), big.NewInt(1)}
			p2coe := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			p2, err := NewPolynomial(fieldOrder, p2coe)
			Expect(err).Should(BeNil())
			quotient, remainder, err := p1.FDiv(p2)
			Expect(err).Should(BeNil())
			solutionQuo := []*big.Int{big.NewInt(0)}
			solutionRem := []*big.Int{big.NewInt(3), big.NewInt(2), big.NewInt(1)}
			Expect(quotient.coefficients).Should(Equal(solutionQuo))
			Expect(remainder.coefficients).Should(Equal(solutionRem))
		})
		It("divisor is zero", func() {
			fieldOrder := big.NewInt(7)
			p1coe := []*big.Int{big.NewInt(3), big.NewInt(2), big.NewInt(1)}
			p2coe := []*big.Int{big.NewInt(0)}
			p1, err := NewPolynomial(fieldOrder, p1coe)
			Expect(err).Should(BeNil())
			p2, err := NewPolynomial(fieldOrder, p2coe)
			Expect(err).Should(BeNil())
			quotient, remainder, err := p1.FDiv(p2)
			Expect(err).Should(Equal(utils.ErrDivisionByZero))
			Expect(quotient).Should(BeNil())
			Expect(remainder).Should(BeNil())
		})
	})
})
