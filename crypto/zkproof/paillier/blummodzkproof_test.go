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

		It("wrong security level (zero or negative)", func() {
			err := zkproof.Verify(ssIDInfo, big0)
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong security level (too small modulus)", func() {
			err := zkproof.Verify(ssIDInfo, new(big.Int).Lsh(n0, 2))
			Expect(err).ShouldNot(BeNil())
		})

		It("bypass attack: empty slices (0 challenges)", func() {
			// 惡意清空所有陣列，試圖讓迴圈不執行就 return nil
			zkproof.A = make([][]byte, 0)
			zkproof.B = make([][]byte, 0)
			zkproof.X = make([][]byte, 0)
			zkproof.Z = make([][]byte, 0)

			err := zkproof.Verify(ssIDInfo, n1)
			Expect(err).Should(Equal(ErrInvalidInput)) // 預期被我們的長度防護擋下
		})

		It("bypass attack: too few challenges", func() {
			zkproof.A = zkproof.A[:MINIMALCHALLENGE-1]
			zkproof.B = zkproof.B[:MINIMALCHALLENGE-1]
			zkproof.X = zkproof.X[:MINIMALCHALLENGE-1]
			zkproof.Z = zkproof.Z[:MINIMALCHALLENGE-1]

			err := zkproof.Verify(ssIDInfo, n1)
			Expect(err).Should(Equal(ErrInvalidInput))
		})

		It("panic DoS: slice B length mismatch", func() {
			zkproof.B = zkproof.B[:len(zkproof.B)-1]

			err := zkproof.Verify(ssIDInfo, n1)
			Expect(err).Should(Equal(ErrInvalidInput)) // 確保回傳錯誤，而不是發生 panic: index out of range
		})

		It("panic DoS: slice X length mismatch", func() {
			zkproof.X = append(zkproof.X, []byte{1, 2, 3})

			err := zkproof.Verify(ssIDInfo, n1)
			Expect(err).Should(Equal(ErrInvalidInput))
		})

		It("panic DoS: slice Z length mismatch", func() {
			zkproof.Z = make([][]byte, 0)

			err := zkproof.Verify(ssIDInfo, n1)
			Expect(err).Should(Equal(ErrInvalidInput))
		})
	})

})
