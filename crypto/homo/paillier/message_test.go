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
package paillier

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/getamis/alice/crypto/utils"
)

var _ = Describe("Message test", func() {
	Context("ToPubkey()", func() {
		var p *Paillier
		BeforeEach(func() {
			var err error
			p, err = NewPaillier(2048)
			Expect(err).Should(BeNil())
		})

		It("should be ok", func() {
			pub, err := p.PublicKey.msg.ToPubkey()
			Expect(err).Should(BeNil())
			Expect(pub).Should(Equal(p.PublicKey))
		})

		It("g and nSqaure are not relative prime", func() {
			p.PublicKey.msg.G = p.n.Bytes()
			pub, err := p.PublicKey.msg.ToPubkey()
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(pub).Should(BeNil())
		})

		It("g is not in range", func() {
			p.PublicKey.msg.G = p.nSquare.Bytes()
			pub, err := p.PublicKey.msg.ToPubkey()
			Expect(err).Should(Equal(utils.ErrNotInRange))
			Expect(pub).Should(BeNil())
		})

		It("zero n", func() {
			p.PublicKey.msg.Proof.PublicKey = big0.Bytes()
			pub, err := p.PublicKey.msg.ToPubkey()
			Expect(err).Should(Equal(utils.ErrLargerFloor))
			Expect(pub).Should(BeNil())
		})

		It("invalid proof", func() {
			p.PublicKey.msg.Proof.Proof = []byte("invalid proof")
			pub, err := p.PublicKey.msg.ToPubkey()
			Expect(err).ShouldNot(BeNil())
			Expect(pub).Should(BeNil())
		})
	})
})
