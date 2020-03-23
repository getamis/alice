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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("cache", func() {
	var c *cacheExp
	BeforeEach(func() {
		bq, err := NewBQuadraticForm(big.NewInt(1), big.NewInt(1), big.NewInt(6))
		Expect(err).Should(BeNil())
		c = NewCacheExp(bq)
	})

	It("implement Exper interface", func() {
		var _ Exper = c
	})

	It("buildCache()", func() {
		lens := 10
		Expect(c.buildCache(lens)).Should(BeNil())
		Expect(c.cache).Should(HaveLen(lens))
	})

	It("ToMessage()", func() {
		Expect(c.ToMessage()).Should(Equal(c.bq.ToMessage()))
	})

	Context("Exp()", func() {
		It("exp = 0", func() {
			got, err := c.Exp(big0)
			Expect(err).Should(BeNil())
			Expect(got).Should(Equal(c.bq.Identity()))
			Expect(c.cache).Should(BeEmpty())
		})

		It("exp = 5", func() {
			v := big.NewInt(5)
			got, err := c.Exp(v)
			Expect(err).Should(BeNil())
			Expect(got).Should(Equal(c.bq.Identity()))
			Expect(c.cache).Should(HaveLen(v.BitLen()))
		})
	})
})
