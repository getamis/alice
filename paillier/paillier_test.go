// Copyright © 2019 AMIS Technologies
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

package paillier

import (
	"math/big"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Paillier test", func() {
	var p *Paillier
	BeforeEach(func() {
		var err error
		p, err = NewPaillier(2048)
		Expect(err).Should(BeNil())
	})

	It("should be ok with valid random mesages", func() {
		m, err := RandomInt(p.PublicKey.n)
		Expect(err).Should(BeNil())
		c, err := p.Encrypt(m)
		Expect(err).Should(BeNil())
		Expect(m.Cmp(c)).ShouldNot(BeZero())
		got, err := p.Decrypt(c)
		Expect(err).Should(BeNil())
		Expect(got.Cmp(m)).Should(BeZero())
	})

	It("should be ok with zero mesages", func() {
		m := Big0
		c, err := p.Encrypt(m)
		Expect(err).Should(BeNil())
		Expect(m.Cmp(c)).ShouldNot(BeZero())
		got, err := p.Decrypt(c)
		Expect(err).Should(BeNil())
		Expect(got.Cmp(m)).Should(BeZero())
	})

	It("should be ok with n-1", func() {
		m := new(big.Int).Sub(p.PublicKey.n, Big1)
		c, err := p.Encrypt(m)
		Expect(err).Should(BeNil())
		Expect(m.Cmp(c)).ShouldNot(BeZero())
		got, err := p.Decrypt(c)
		Expect(err).Should(BeNil())
		Expect(got.Cmp(m)).Should(BeZero())
	})

	Context("Invalid encrypt", func() {
		It("negative message", func() {
			c, err := p.Encrypt(big.NewInt(-5))
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(c).Should(BeNil())
		})

		It("over range message", func() {
			c, err := p.Encrypt(p.PublicKey.n)
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(c).Should(BeNil())
		})
	})

	Context("Invalid decrypt", func() {
		It("over range message", func() {
			c, err := p.Decrypt(p.PublicKey.n)
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(c).Should(BeNil())
		})

		It("zero message", func() {
			c, err := p.Decrypt(Big0)
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(c).Should(BeNil())
		})
	})

	DescribeTable("lFunction", func(x *big.Int, n *big.Int, exp *big.Int, expErr error) {
		got, gotErr := lFunction(x, n)
		if expErr != nil {
			Expect(gotErr).Should(Equal(expErr))
			Expect(got).Should(BeNil())
		} else {
			Expect(gotErr).Should(BeNil())
			Expect(got.Cmp(exp)).Should(BeZero())
		}
	},
		Entry("(11, 5) should be ok", big.NewInt(11), big.NewInt(5), big.NewInt(2), nil),
		Entry("(1, 2) should be ok", big.NewInt(1), big.NewInt(2), big.NewInt(0), nil),
		Entry("(1, 1) should be ok", big.NewInt(1), big.NewInt(1), big.NewInt(0), nil),
		Entry("(0, 1) invalid input", big.NewInt(0), big.NewInt(1), nil, ErrInvalidInput),
		Entry("(-10, 1) invalid input", big.NewInt(-10), big.NewInt(1), nil, ErrInvalidInput),
		Entry("(12, 5) invalid input", big.NewInt(12), big.NewInt(5), nil, ErrInvalidInput),
	)
})

func TestPaillier(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Paillier Test")
}
