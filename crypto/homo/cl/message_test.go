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

package cl

import (
	"math/big"

	"github.com/golang/protobuf/proto"

	binaryquadraticform "github.com/getamis/alice/crypto/binaryquadraticform"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const invalidMsg = "invalid A"

var _ = Describe("Message test", func() {
	Context("newBQs", func() {
		var bq1, bq2 *binaryquadraticform.BQuadraticForm
		var desp *big.Int
		BeforeEach(func() {
			var err error
			bq1, err = binaryquadraticform.NewBQuadraticForm(big.NewInt(33), big.NewInt(11), big.NewInt(5))
			Expect(err).Should(BeNil())
			bq2, err = binaryquadraticform.NewBQuadraticForm(big.NewInt(33), big.NewInt(-11), big.NewInt(5))
			Expect(err).Should(BeNil())
			desp = bq1.GetDiscriminant()
		})

		It("should be ok", func() {
			msg := &EncryptedMessage{
				M1:    bq1.ToMessage(),
				M2:    bq2.ToMessage(),
				Proof: &ProofMessage{},
			}
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())

			m1, m2, err := newBQs(desp, bs)
			Expect(err).Should(BeNil())
			Expect(bq1.Equal(m1)).Should(BeTrue())
			Expect(bq2.Equal(m2)).Should(BeTrue())
		})

		It("wrong m2 desp", func() {
			bq2, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(33), big.NewInt(-11), big.NewInt(6))
			Expect(err).Should(BeNil())
			msg := &EncryptedMessage{
				M1:    bq1.ToMessage(),
				M2:    bq2.ToMessage(),
				Proof: &ProofMessage{},
			}
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())

			m1, m2, err := newBQs(desp, bs)
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(m1).Should(BeNil())
			Expect(m2).Should(BeNil())
		})

		It("invalid m2", func() {
			msg := &EncryptedMessage{
				M1:    bq1.ToMessage(),
				M2:    bq2.ToMessage(),
				Proof: &ProofMessage{},
			}
			msg.M2.A = invalidMsg
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())

			m1, m2, err := newBQs(desp, bs)
			Expect(err).Should(Equal(binaryquadraticform.ErrInvalidMessage))
			Expect(m1).Should(BeNil())
			Expect(m2).Should(BeNil())
		})

		It("wrong m1 desp", func() {
			bq1, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(33), big.NewInt(-11), big.NewInt(6))
			Expect(err).Should(BeNil())
			msg := &EncryptedMessage{
				M1:    bq1.ToMessage(),
				M2:    bq2.ToMessage(),
				Proof: &ProofMessage{},
			}
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())

			m1, m2, err := newBQs(desp, bs)
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(m1).Should(BeNil())
			Expect(m2).Should(BeNil())
		})

		It("invalid m1", func() {
			msg := &EncryptedMessage{
				M1:    bq1.ToMessage(),
				M2:    bq2.ToMessage(),
				Proof: &ProofMessage{},
			}
			msg.M1.A = invalidMsg
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())

			m1, m2, err := newBQs(desp, bs)
			Expect(err).Should(Equal(binaryquadraticform.ErrInvalidMessage))
			Expect(m1).Should(BeNil())
			Expect(m2).Should(BeNil())
		})

		It("empty proto message", func() {
			msg := &PubKeyMessage{}
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())

			m1, m2, err := newBQs(desp, bs)
			Expect(err).Should(Equal(binaryquadraticform.ErrInvalidMessage))
			Expect(m1).Should(BeNil())
			Expect(m2).Should(BeNil())
		})

		It("invalid proto message", func() {
			msg := &PubKeyMessage{
				P: []byte("P"),
			}
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())

			m1, m2, err := newBQs(desp, bs)
			Expect(err).ShouldNot(BeNil())
			Expect(m1).Should(BeNil())
			Expect(m2).Should(BeNil())
		})
	})

	Context("ToPubkey", func() {
		bigPrime, _ := new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)
		safeParameter := 1348
		var msg *PubKeyMessage
		var cl *CL
		BeforeEach(func() {
			var err error
			cl, err = NewCL(big.NewInt(1024), 40, bigPrime, safeParameter, 80)
			Expect(err).Should(BeNil())
			msg = cl.ToPubKeyMessage()
		})

		It("should be ok", func() {
			pub, err := msg.ToPubkey()
			Expect(err).Should(BeNil())
			Expect(pub).Should(Equal(cl.PublicKey))
		})

		It("invalid H", func() {
			msg.H.A = invalidMsg
			pub, err := msg.ToPubkey()
			Expect(err).Should(Equal(binaryquadraticform.ErrInvalidMessage))
			Expect(pub).Should(BeNil())
		})

		It("invalid F", func() {
			msg.F.A = invalidMsg
			pub, err := msg.ToPubkey()
			Expect(err).Should(Equal(binaryquadraticform.ErrInvalidMessage))
			Expect(pub).Should(BeNil())
		})

		It("invalid G", func() {
			msg.G.A = invalidMsg
			pub, err := msg.ToPubkey()
			Expect(err).Should(Equal(binaryquadraticform.ErrInvalidMessage))
			Expect(pub).Should(BeNil())
		})

		It("zero Q", func() {
			msg.Q = big0.Bytes()
			pub, err := msg.ToPubkey()
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(pub).Should(BeNil())
		})

		It("zero P", func() {
			msg.P = big0.Bytes()
			pub, err := msg.ToPubkey()
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(pub).Should(BeNil())
		})
	})
})
