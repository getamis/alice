// Copyright © 2022 AMIS Technologies
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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Prime", func() {
	DescribeTable("SafePrime()", func(size int) {
		safePrime, err := GenerateRandomSafePrime(rand.Reader, size)
		Expect(err).Should(BeNil())
		Expect(safePrime.P.ProbablyPrime(1)).Should(BeTrue())
		Expect(safePrime.Q.ProbablyPrime(1)).Should(BeTrue())
	},
		Entry("size = 37", 33),
		Entry("size = 1024", 1024),
	)

	Context("SafePrime()", func() {
		It("it does not work", func() {
			safePrime, err := GenerateRandomSafePrime(rand.Reader, 2)
			Expect(safePrime).Should(BeNil())
			Expect(err).Should(Equal(ErrSmallSafePrime))
		})
	})
})
