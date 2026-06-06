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

package paillier

import (
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Blummodzkproof test", func() {
	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			zkproof, err := NewPaillierBlumMessage(ssIDInfo, p1, q1, n1, MINIMALCHALLENGE)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(ssIDInfo, n1)
			Expect(err).Should(BeNil())
		})
		It("wrong p and q", func() {
			zkproof, err := NewPaillierBlumMessage(ssIDInfo, big0, big0, n0, MINIMALCHALLENGE)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("wrong challenge size", func() {
			zkproof, err := NewPaillierBlumMessage(ssIDInfo, p0, q0, n0, 0)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("wrong n0", func() {
			zkproof, err := NewPaillierBlumMessage(ssIDInfo, p0, q0, big0, MINIMALCHALLENGE)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("Verify tests", func() {
		var zkproof *PaillierBlumMessage
		BeforeEach(func() {
			var err error
			zkproof, err = NewPaillierBlumMessage(ssIDInfo, p1, q1, n1, MINIMALCHALLENGE)
			Expect(err).Should(BeNil())
		})
		It("wrong security level", func() {
			err := zkproof.Verify(ssIDInfo, big0)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong security level", func() {
			err := zkproof.Verify(ssIDInfo, new(big.Int).Lsh(n0, 2))
			Expect(err).ShouldNot(BeNil())
		})

	})

})
