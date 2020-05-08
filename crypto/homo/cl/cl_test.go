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
	"testing"

	"github.com/btcsuite/btcd/btcec"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("CL test", func() {
	var cl *CL
	bigPrime, _ := new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)
	safeParameter := 1348

	BeforeEach(func() {
		// Generate a private key and the public key associated with discriminant bigPrime * q, where
		// bigPrime is the message space and q is a probabilistic "prime" with the bitlength is SAFEPARAMETER - bitlength of bigprime.
		var err error
		cl, err = NewCL(big.NewInt(1024), 40, bigPrime, safeParameter, 80)
		Expect(err).Should(BeNil())
	})

	It("implement homo.Crypto interface", func() {
		var _ homo.Crypto = cl
	})

	It("implement homo.Pubkey interface", func() {
		var _ homo.Pubkey = cl.PublicKey
	})

	Context("NewCL", func() {
		It("safe parameter < 1348", func() {
			cl, err := NewCL(big.NewInt(1024), 40, bigPrime, 2, 80)
			Expect(err).Should(Equal(ErrSmallSafeParameter))
			Expect(cl).Should(BeNil())
		})

		It(" λ < μ + 2", func() {
			p, err := utils.RandomPrime(1348)
			Expect(err).Should(BeNil())
			cl, err := NewCL(big.NewInt(1024), 40, p, 1348, 80)
			Expect(err).Should(Equal(ErrSmallSafeParameter))
			Expect(cl).Should(BeNil())
		})

		It(" p is not odd prime: p = 2", func() {
			cl, err := NewCL(big.NewInt(1024), 40, big2, 1348, 80)
			Expect(err).Should(Equal(ErrNotOddPrime))
			Expect(cl).Should(BeNil())
		})

		It(" p is not odd prime: p = 1000", func() {
			cl, err := NewCL(big.NewInt(1024), 40, big.NewInt(1000), 1348, 80)
			Expect(err).Should(Equal(ErrNotOddPrime))
			Expect(cl).Should(BeNil())
		})
	})

	It("ToPubKey()/ToPubKeyMessage()", func() {
		msg := cl.PublicKey.ToPubKeyMessage()
		pub, err := msg.ToPubkey()
		Expect(err).Should(BeNil())
		Expect(pub).Should(Equal(cl.PublicKey))
	})

	It("ToPubKeyBytes()/NewPubKeyFromBytes()", func() {
		bs := cl.PublicKey.ToPubKeyBytes()
		pub, err := cl.NewPubKeyFromBytes(bs)
		Expect(err).Should(BeNil())
		Expect(pub).Should(Equal(cl.PublicKey))
	})

	It("GetPubKey()", func() {
		got := cl.GetPubKey()
		Expect(got).Should(Equal(cl.PublicKey))
	})

	It("GetMessageRange()", func() {
		fieldOrder := big.NewInt(1024)
		got := cl.GetMessageRange(fieldOrder)
		Expect(got).Should(Equal(fieldOrder))
	})

	Context("GetMtaProof()/VerifyMtaProof()", func() {
		curve := btcec.S256()
		beta := big.NewInt(2)
		alpha := big.NewInt(8)
		b := big.NewInt(2)
		k := big.NewInt(5)
		It("should be ok", func() {
			bs, err := cl.GetMtaProof(curve, beta, b)
			Expect(err).Should(BeNil())
			p, err := cl.VerifyMtaProof(bs, curve, alpha, k)
			Expect(err).Should(BeNil())
			Expect(p.Equal(pt.ScalarBaseMult(curve, b))).Should(BeTrue())
		})

		It("invalid k", func() {
			k := big.NewInt(4)
			bs, err := cl.GetMtaProof(curve, beta, b)
			Expect(err).Should(BeNil())
			p, err := cl.VerifyMtaProof(bs, curve, alpha, k)
			Expect(err).Should(Equal(ErrFailedVerify))
			Expect(p).Should(BeNil())
		})

		It("empty bytes", func() {
			p, err := cl.VerifyMtaProof([]byte{}, curve, alpha, k)
			Expect(err).ShouldNot(BeNil())
			Expect(p).Should(BeNil())
		})
	})

	Context("VerifyEnc()", func() {
		var msg *EncryptedMessage
		BeforeEach(func() {
			bs, err := cl.Encrypt([]byte("message"))
			Expect(err).Should(BeNil())

			msg = &EncryptedMessage{}
			err = proto.Unmarshal(bs, msg)
			Expect(err).Should(BeNil())
		})

		It("invalid bytes", func() {
			Expect(cl.PublicKey.VerifyEnc([]byte("invalid bytes"))).ShouldNot(BeNil())
		})

		It("invalid T1", func() {
			msg.Proof.T1.A = "invalid T1'A"
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())
			Expect(cl.PublicKey.VerifyEnc(bs)).Should(Equal(ErrInvalidMessage))
		})

		It("invalid T2", func() {
			msg.Proof.T2.A = "invalid T2'A"
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())
			Expect(cl.PublicKey.VerifyEnc(bs)).Should(Equal(ErrInvalidMessage))
		})

		It("invalid M1", func() {
			msg.M1.A = "invalid M1'A"
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())
			Expect(cl.PublicKey.VerifyEnc(bs)).Should(Equal(ErrInvalidMessage))
		})

		It("invalid M2", func() {
			msg.M2.A = "invalid M2'A"
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())
			Expect(cl.PublicKey.VerifyEnc(bs)).Should(Equal(ErrInvalidMessage))
		})

		It("u1 not in range", func() {
			u1, ok := new(big.Int).SetString("29296987138580769930714757048540979360961165432097041714448204244391065048171935531432808153127058686940959288580689100494404715415738025857259483940730327082475765140189843258994413683767727289862194642755441878060270331588936791648276567818241999999", 10)
			Expect(ok).Should(BeTrue())
			msg.Proof.U1 = u1.Bytes()
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())
			Expect(cl.PublicKey.VerifyEnc(bs)).Should(Equal(utils.ErrNotInRange))
		})

		It("u2 not in range", func() {
			msg.Proof.U2 = cl.p.Bytes()
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())
			Expect(cl.PublicKey.VerifyEnc(bs)).Should(Equal(utils.ErrNotInRange))
		})

		It("different k", func() {
			b, ok := new(big.Int).SetString(msg.Proof.T2.B, 10)
			Expect(ok).Should(BeTrue())
			msg.Proof.T2.B = new(big.Int).Neg(b).String()
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())
			Expect(cl.PublicKey.VerifyEnc(bs)).Should(Equal(ErrDifferentBQForms))
		})

		It("wrong u1", func() {
			msg.Proof.U1 = big.NewInt(999).Bytes()
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())
			Expect(cl.PublicKey.VerifyEnc(bs)).Should(Equal(ErrDifferentBQForms))
		})
	})

	DescribeTable("Decrypt", func(message *big.Int) {
		// Encrypt the origin message by the public key
		c, err := cl.Encrypt(message.Bytes())
		Expect(err).Should(BeNil())

		// Verify message
		Expect(cl.PublicKey.VerifyEnc(c)).Should(BeNil())

		// decrypt the c
		got, err := cl.Decrypt(c)
		Expect(err).Should(BeNil())
		Expect(message.Bytes()).Should(Equal(got))
	},
		Entry("0 should be ok", big.NewInt(0)),
		Entry("987 should be ok", big.NewInt(987)),
		Entry("22971 should be ok", big.NewInt(22971)),
	)

	DescribeTable("Decrypt: big int", func(message *big.Int) {
		// Encrypt the origin message by the public key
		message = message.Add(message, bigPrime)
		c, err := cl.Encrypt(message.Bytes())
		Expect(err).Should(BeNil())

		// Verify message
		Expect(cl.PublicKey.VerifyEnc(c)).Should(BeNil())

		// decrypt the cipherMessage
		ret, err := cl.Decrypt(c)
		Expect(err).Should(BeNil())
		got := message.Mod(message, bigPrime).Bytes()
		Expect(ret).Should(Equal(got))
	},
		Entry("0 should be ok", big.NewInt(0)),
		Entry("2000 should be ok", big.NewInt(2000)),
		Entry("-1 should be ok", big.NewInt(-1)),
	)

	DescribeTable("Add", func(message1, message2 *big.Int) {
		message1 = message1.Add(message1, cl.p)
		message2 = message1.Add(message2, cl.p)
		expected := new(big.Int).Add(message1, message2)
		expected = expected.Mod(expected, cl.p)

		// Do encryption
		c1, err := cl.Encrypt(message1.Bytes())
		Expect(err).Should(BeNil())
		c2, err := cl.Encrypt(message2.Bytes())
		Expect(err).Should(BeNil())

		// Perform add to get Encrypt( message1 + message2 )
		sum, err := cl.Add(c1, c2)
		Expect(err).Should(BeNil())

		// Check sum of decryption is message1 + message2.
		got, err := cl.Decrypt(sum)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(expected.Bytes()))
	},
		Entry("(987,233) should be ok", big.NewInt(987), big.NewInt(233)),
		Entry("(-100,233) should be ok", big.NewInt(-100), big.NewInt(233)),
		Entry("(0,0) should be ok", big.NewInt(0), big.NewInt(0)),
	)

	DescribeTable("MulConst", func(message, scalar *big.Int) {
		scalar = scalar.Add(scalar, cl.p)
		message = message.Add(message, cl.p)
		expected := new(big.Int).Mul(message, scalar)
		expected = expected.Mod(expected, cl.p)

		// Encrypt message
		c, err := cl.Encrypt(message.Bytes())
		Expect(err).Should(BeNil())

		// Perform EvalMulConst to get Encrypt( message ^ scalar )
		scalarResult, err := cl.MulConst(c, scalar)
		Expect(err).Should(BeNil())

		ret, err := cl.Decrypt(scalarResult)
		Expect(err).Should(BeNil())
		Expect(expected.Bytes()).Should(Equal(ret))
	},
		Entry("(0,12) should be ok", big.NewInt(0), big.NewInt(12)),
		Entry("(-100,233) should be ok", big.NewInt(-100), big.NewInt(233)),
		Entry("(0,0) should be ok", big.NewInt(0), big.NewInt(0)),
	)
})

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CL Test")
}
