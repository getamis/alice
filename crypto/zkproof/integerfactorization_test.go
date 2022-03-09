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

	It("negative case: the size of public key is small", func() {
		p, err := rand.Prime(rand.Reader, 1000)
		Expect(err).To(BeNil())
		q, err := rand.Prime(rand.Reader, 1000)
		Expect(err).To(BeNil())
		publicKey := new(big.Int).Mul(p, q)
		primeFactor := []*big.Int{p, q}
		msg, err := NewIntegerFactorizationProofMessage(primeFactor, publicKey)
		Expect(msg).To(BeNil())
		Expect(err).Should(Equal(ErrSmallPublicKeySize))
	})

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

		It("X not in range", func() {
			msg.X = new(big.Int).Add(publicKey, big2).Bytes()
			Expect(msg.Verify()).ShouldNot(BeNil())
		})

		It("Y not in range", func() {
			msg.Y = new(big.Int).Add(publicKey, big2).Bytes()
			Expect(msg.Verify()).ShouldNot(BeNil())
		})

		It("wrong case", func() {
			msg.X = new(big.Int).Sub(publicKey, big2).Bytes()
			Expect(msg.Verify()).Should(Equal(ErrVerifyFailure))
		})

		It("exceed maxRetry", func() {
			result, err := generateZ(big.NewInt(101*103), big1, 0)
			Expect(result).To(BeNil())
			Expect(err).Should(Equal(ErrExceedMaxRetry))
		})
	})
})
