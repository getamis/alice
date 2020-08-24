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
package utils

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"golang.org/x/crypto/blake2b"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Utils Suite")
}

var _ = Describe("Utils", func() {
	DescribeTable("EnsureFieldOrder()", func(a *big.Int, err error) {
		got := EnsureFieldOrder(a)
		if err == nil {
			Expect(got).Should(BeNil())
		} else {
			Expect(got).Should(Equal(err))
		}
	},
		Entry("should be ok", big.NewInt(3), nil),
		Entry("invalid field order", big.NewInt(2), ErrLessOrEqualBig2),
	)

	DescribeTable("EnsureRank()", func(rank uint32, threshold uint32, err error) {
		got := EnsureRank(rank, threshold)
		if err == nil {
			Expect(got).Should(BeNil())
		} else {
			Expect(got).Should(Equal(err))
		}
	},
		Entry("should be ok", uint32(0), uint32(2), nil),
		Entry("large rank", uint32(1), uint32(2), ErrLargeRank),
	)

	DescribeTable("EnsureThreshold()", func(threshold uint32, n uint32, err error) {
		got := EnsureThreshold(threshold, n)
		if err == nil {
			Expect(got).Should(BeNil())
		} else {
			Expect(got).Should(Equal(err))
		}
	},
		Entry("should be ok", uint32(2), uint32(2), nil),
		Entry("large threshold", uint32(3), uint32(2), ErrLargeThreshold),
		Entry("small threshold", uint32(1), uint32(2), ErrSmallThreshold),
	)

	It("RandomInt()", func() {
		got, err := RandomInt(big.NewInt(10))
		Expect(err).Should(BeNil())
		// Should be in [0, 10)
		Expect(got.Cmp(big.NewInt(10))).Should(Equal(-1))
		Expect(got.Cmp(big.NewInt(-1))).Should(Equal(1))
	})

	It("RandomPositiveInt()", func() {
		got, err := RandomPositiveInt(big.NewInt(10))
		Expect(err).Should(BeNil())
		// Should be in [1, 10)
		Expect(got.Cmp(big.NewInt(10))).Should(Equal(-1))
		Expect(got.Cmp(big.NewInt(0))).Should(Equal(1))
	})

	It("RandomPrime()", func() {
		bitLen := 5
		got, err := RandomPrime(bitLen)
		Expect(err).Should(BeNil())
		Expect(got.BitLen()).Should(BeNumerically("==", bitLen))
	})

	Context("RandomCoprimeInt()", func() {
		It("should be ok", func() {
			got, err := RandomCoprimeInt(big.NewInt(10))
			Expect(err).Should(BeNil())
			Expect(got).ShouldNot(BeNil())
		})

		It("over max retry", func() {
			maxGenPrimeInt = 0
			got, err := RandomCoprimeInt(big.NewInt(10))
			Expect(err).Should(Equal(ErrExceedMaxRetry))
			Expect(got).Should(BeNil())
		})

		It("invalid n", func() {
			maxGenPrimeInt = 0
			got, err := RandomCoprimeInt(big.NewInt(2))
			Expect(err).Should(Equal(ErrLessOrEqualBig2))
			Expect(got).Should(BeNil())
		})
	})

	It("IsRelativePrime()", func() {
		num1 := big.NewInt(5)
		num2 := big.NewInt(8)
		result := IsRelativePrime(num1, num2)
		Expect(result).Should(BeTrue())
	})

	It("Gcd()", func() {
		num1 := big.NewInt(5)
		num2 := big.NewInt(10)
		result := Gcd(num1, num2)
		Expect(result).Should(Equal(num1))

		num2 = big.NewInt(8)
		result = Gcd(num1, num2)
		Expect(result).Should(Equal(big1))
	})

	DescribeTable("Lcm()", func(a *big.Int, b *big.Int, c *big.Int, err error) {
		got, gotErr := Lcm(a, b)
		if err == nil {
			Expect(gotErr).Should(BeNil())
			Expect(got.Cmp(c)).Should(BeZero())
		} else {
			Expect(gotErr).Should(Equal(err))
			Expect(got).Should(BeNil())
		}
	},
		Entry("30", big.NewInt(5), big.NewInt(6), big.NewInt(30), nil),
		Entry("12", big.NewInt(3), big.NewInt(4), big.NewInt(12), nil),
		Entry("a cannot be zero", big.NewInt(0), big.NewInt(4), nil, ErrInvalidInput),
		Entry("b cannot be zero", big.NewInt(3), big.NewInt(0), nil, ErrInvalidInput),
	)

	DescribeTable("EulerFunction()", func(primeFactor []*big.Int, out *big.Int, err error) {
		gotOut, gotErr := EulerFunction(primeFactor)
		if err == nil {
			Expect(gotOut).Should(Equal(out))
			Expect(gotErr).Should(BeNil())
		} else {
			Expect(gotOut).Should(BeNil())
			Expect(gotErr).Should(Equal(err))
		}
	},
		Entry("should be ok", []*big.Int{big.NewInt(5), big.NewInt(6)}, big.NewInt(20), nil),
		Entry("empty input", []*big.Int{}, nil, ErrInvalidInput),
		Entry("there's 1 in the inputs", []*big.Int{big.NewInt(5), big.NewInt(1)}, nil, ErrInvalidInput),
	)

	DescribeTable("InRange()", func(checkValue *big.Int, floor *big.Int, ceil *big.Int, err error) {
		gotErr := InRange(checkValue, floor, ceil)
		if err == nil {
			Expect(gotErr).Should(BeNil())
		} else {
			Expect(gotErr).Should(Equal(err))
		}
	},
		Entry("should be ok", big.NewInt(5), big.NewInt(5), big.NewInt(7), nil),
		Entry("larger floor", big.NewInt(3), big.NewInt(4), big.NewInt(4), ErrLargerFloor),
		Entry("value is smaller than floor", big.NewInt(3), big.NewInt(4), big.NewInt(6), ErrNotInRange),
		Entry("value is equal to ceil", big.NewInt(6), big.NewInt(4), big.NewInt(6), ErrNotInRange),
	)

	DescribeTable("GenRandomBytes()", func(size int, err error) {
		got, gotErr := GenRandomBytes(size)
		if err == nil {
			Expect(gotErr).Should(BeNil())
			Expect(got).ShouldNot(BeNil())
		} else {
			Expect(gotErr).Should(Equal(err))
			Expect(got).Should(BeNil())
		}
	},
		Entry("should be ok", 100, nil),
		Entry("empty slices", 0, ErrEmptySlice),
	)

	Context("HashProtosToInt()", func() {
		It("should work", func() {
			salt, err := GenRandomBytes(blake2b.Size256)
			Expect(err).Should(Succeed())
			msg := &ecpointgrouplaw.EcPointMessage{}
			result, err := HashProtosToInt(salt, msg)
			Expect(err).Should(Succeed())
			Expect(result).ShouldNot(BeNil())
		})
	})

	DescribeTable("SafePrime()", func(size int) {
		safePrime, err := SafePrime(rand.Reader, size)
		Expect(err).Should(BeNil())
		maxFactor := new(big.Int).Sub(safePrime, big1)
		maxFactor.Rsh(maxFactor, 1)
		Expect(safePrime.ProbablyPrime(1)).Should(BeTrue())
		Expect(maxFactor.ProbablyPrime(1)).Should(BeTrue())
	},
		Entry("size = 37", 33),
		Entry("size = 1024", 1024),
	)

	Context("SafePrime()", func() {
		It("it does not work", func() {
			safePrime, err := SafePrime(rand.Reader, 8)
			Expect(safePrime).Should(BeNil())
			Expect(err).Should(Equal(ErrSmallSafePrime))
		})
	})
})
