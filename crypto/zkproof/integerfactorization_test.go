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
package zkproof

import (
	"crypto/rand"
	"math/big"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestZkProof(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Zk proof Suite")
}

var _ = Describe("Integerfactorization flow", func() {
	DescribeTable("should be ok", func(pqSize int) {
		p, err := rand.Prime(rand.Reader, pqSize)
		Expect(err).To(BeNil())
		q, err := rand.Prime(rand.Reader, pqSize)
		Expect(err).To(BeNil())
		publicKey := new(big.Int).Mul(p, q)
		primeFactor := []*big.Int{p, q}
		msg, err := NewIntegerFactorizationProofMessage(primeFactor, publicKey)
		Expect(err).To(BeNil())
		err = msg.Verify()
		Expect(err).To(BeNil())
	},
		Entry("the bit length of the public key is 2048:", 1024),
		Entry("the bit length of the public key is 2046:", 1536),
	)

	Context("negative cases", func() {

		var (
			pqSize = 1024

			msg       *IntegerFactorizationProofMessage
			publicKey *big.Int
		)

		BeforeEach(func() {
			p, err := rand.Prime(rand.Reader, pqSize)
			Expect(err).To(BeNil())
			q, err := rand.Prime(rand.Reader, pqSize)
			Expect(err).To(BeNil())
			publicKey = new(big.Int).Mul(p, q)
			primeFactor := []*big.Int{p, q}
			msg, err = NewIntegerFactorizationProofMessage(primeFactor, publicKey)
			Expect(err).To(BeNil())
		})

		It("empty factors", func() {
			msg, err := NewIntegerFactorizationProofMessage([]*big.Int{}, publicKey)
			Expect(err).ShouldNot(BeNil())
			Expect(msg).To(BeNil())
		})

		It("proof not in range", func() {
			msg.Proof = new(big.Int).Add(publicKey, big2).Bytes()
			Expect(msg.Verify()).ShouldNot(BeNil())
		})

		It("challenge is larger than pub key", func() {
			msg.Challenge = new(big.Int).Add(publicKey, big2).Bytes()
			Expect(msg.Verify()).ShouldNot(BeNil())
		})

		It("challenge is smaller than 2", func() {
			msg.Challenge = big.NewInt(1).Bytes()
			Expect(msg.Verify()).ShouldNot(BeNil())
		})

		It("wrong challenge", func() {
			msg.Challenge = new(big.Int).Add(new(big.Int).SetBytes(msg.Challenge), big2).Bytes()
			Expect(msg.Verify()).Should(Equal(ErrVerifyFailure))
		})
	})
})
