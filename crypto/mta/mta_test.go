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

package mta

import (
	"errors"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/homo/mocks"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func TestMta(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Mta Suite")
}

var (
	curve      = btcec.S256()
	fieldOrder = curve.N
	unknownErr = errors.New("unknown error")

	//paillier
	p1, _ = paillier.NewPaillier(2048)
	p2, _ = paillier.NewPaillier(2048)

	//CL
	safeParameter        = 1348
	distributionDistance = uint(40)
	c1, _                = cl.NewCL(big.NewInt(1024), 40, fieldOrder, safeParameter, distributionDistance)
	c2, _                = cl.NewCL(big.NewInt(1024), 40, fieldOrder, safeParameter, distributionDistance)
)

var _ = Describe("Mta", func() {
	var (
		mockHomo *mocks.Crypto
		m        *mta
	)
	BeforeEach(func() {
		mockHomo = new(mocks.Crypto)
		mockHomo.On("Encrypt", mock.Anything).Return([]byte("encK"), nil).Once()
		var err error
		m, err = NewMta(fieldOrder, mockHomo)
		Expect(err).Should(BeNil())
	})
	AfterEach(func() {
		mockHomo.AssertExpectations(GinkgoT())
	})

	Context("Compute", func() {
		var (
			mockPubkey *mocks.Pubkey
		)
		BeforeEach(func() {
			mockPubkey = new(mocks.Pubkey)
		})
		AfterEach(func() {
			mockPubkey.AssertExpectations(GinkgoT())
		})

		It("should be ok", func() {
			msg := []byte("message")
			mockPubkey.On("VerifyEnc", msg).Return(nil).Once()
			betaRange := big.NewInt(100)
			mockPubkey.On("GetMessageRange", m.fieldOrder).Return(betaRange).Once()
			encBeta := []byte("encBeta")
			var beta []byte
			mockPubkey.On("Encrypt", mock.Anything).Run(func(args mock.Arguments) {
				beta = args[0].([]byte)
			}).Return(encBeta, nil).Once()
			r := []byte("r")
			mockPubkey.On("MulConst", msg, m.a).Return(r, nil).Once()
			mockPubkey.On("Add", r, encBeta).Return(r, nil).Once()
			gotAlpha, gotBeta, err := m.Compute(mockPubkey, msg)
			Expect(err).Should(BeNil())
			Expect(gotAlpha).Should(Equal(new(big.Int).SetBytes(r)))
			Expect(gotBeta).Should(Equal(new(big.Int).Neg(new(big.Int).SetBytes(beta))))
		})

		It("failed to add", func() {
			msg := []byte("message")
			mockPubkey.On("VerifyEnc", msg).Return(nil).Once()
			betaRange := big.NewInt(100)
			mockPubkey.On("GetMessageRange", m.fieldOrder).Return(betaRange).Once()
			encBeta := []byte("encBeta")
			mockPubkey.On("Encrypt", mock.Anything).Return(encBeta, nil).Once()
			r := []byte("r")
			mockPubkey.On("MulConst", msg, m.a).Return(r, nil).Once()
			mockPubkey.On("Add", r, encBeta).Return(nil, unknownErr).Once()
			gotAlpha, gotBeta, err := m.Compute(mockPubkey, msg)
			Expect(err).Should(Equal(unknownErr))
			Expect(gotAlpha).Should(BeNil())
			Expect(gotBeta).Should(BeNil())
		})

		It("failed to MulConst", func() {
			msg := []byte("message")
			mockPubkey.On("VerifyEnc", msg).Return(nil).Once()
			betaRange := big.NewInt(100)
			mockPubkey.On("GetMessageRange", m.fieldOrder).Return(betaRange).Once()
			encBeta := []byte("encBeta")
			mockPubkey.On("Encrypt", mock.Anything).Return(encBeta, nil).Once()
			mockPubkey.On("MulConst", msg, m.a).Return(nil, unknownErr).Once()
			gotAlpha, gotBeta, err := m.Compute(mockPubkey, msg)
			Expect(err).Should(Equal(unknownErr))
			Expect(gotAlpha).Should(BeNil())
			Expect(gotBeta).Should(BeNil())
		})

		It("failed to Encrypt", func() {
			msg := []byte("message")
			mockPubkey.On("VerifyEnc", msg).Return(nil).Once()
			betaRange := big.NewInt(100)
			mockPubkey.On("GetMessageRange", m.fieldOrder).Return(betaRange).Once()
			mockPubkey.On("Encrypt", mock.Anything).Return(nil, unknownErr).Once()
			gotAlpha, gotBeta, err := m.Compute(mockPubkey, msg)
			Expect(err).Should(Equal(unknownErr))
			Expect(gotAlpha).Should(BeNil())
			Expect(gotBeta).Should(BeNil())
		})

		It("failed to VerifyEnc", func() {
			msg := []byte("message")
			mockPubkey.On("VerifyEnc", msg).Return(unknownErr).Once()
			gotAlpha, gotBeta, err := m.Compute(mockPubkey, msg)
			Expect(err).Should(Equal(unknownErr))
			Expect(gotAlpha).Should(BeNil())
			Expect(gotBeta).Should(BeNil())
		})
	})

	It("GetProofWithCheck", func() {
		curve := btcec.S256()
		beta := big.NewInt(3)
		proof := []byte("proof")
		mockHomo.On("GetMtaProof", curve, beta, m.a).Return(proof, nil).Once()
		got, err := m.GetProofWithCheck(curve, beta)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(proof))
	})

	It("VerifyProofWithCheck", func() {
		curve := btcec.S256()
		alpha := big.NewInt(3)
		proof := []byte("proof")
		p := &pt.ECPoint{}
		mockHomo.On("VerifyMtaProof", proof, curve, alpha, m.k).Return(p, nil).Once()
		got, err := m.VerifyProofWithCheck(proof, curve, alpha)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(p))
	})

	Context("OverrideA", func() {
		It("should be ok", func() {
			newA := big.NewInt(1)
			got, err := m.OverrideA(newA)
			Expect(err).Should(BeNil())
			m.a = newA
			Expect(got).Should(Equal(m))
		})

		It("over field order", func() {
			got, err := m.OverrideA(m.fieldOrder)
			Expect(err).Should(Equal(utils.ErrNotInRange))
			Expect(got).Should(BeNil())
		})
	})

	It("GetAProof", func() {
		proof, err := m.GetAProof(curve)
		Expect(err).Should(BeNil())
		err = proof.Verify(pt.NewBase(curve))
		Expect(err).Should(BeNil())
	})

	It("Getter func", func() {
		Expect(m.GetAG(curve)).Should(Equal(pt.ScalarBaseMult(curve, m.a)))
		v := big.NewInt(10)
		Expect(m.GetProductWithK(v)).Should(Equal(new(big.Int).Mul(m.k, v)))
	})

	It("GetResult(), inconsistent alphas and betas", func() {
		got, err := m.GetResult(nil, []*big.Int{big.NewInt(1)})
		Expect(err).Should(Equal(ErrInconsistentAlphaAndBeta))
		Expect(got).Should(BeNil())
	})

	It("Decrypt(), homo decrypt fail", func() {
		data := []byte("data")
		mockHomo.On("Decrypt", data).Return(nil, unknownErr).Once()
		got, err := m.Decrypt(new(big.Int).SetBytes(data))
		Expect(err).Should(Equal(unknownErr))
		Expect(got).Should(BeNil())
	})

	DescribeTable("should be ok", func(homo1 homo.Crypto, homo2 homo.Crypto) {
		m1, err := NewMta(fieldOrder, homo1)
		Expect(err).Should(BeNil())
		Expect(m1).ShouldNot(BeNil())

		m2, err := NewMta(fieldOrder, homo2)
		Expect(err).Should(BeNil())
		Expect(m2).ShouldNot(BeNil())

		m1EncryptedK := m1.GetEncK()
		encMessage, beta, err := m2.Compute(homo1.GetPubKey(), m1EncryptedK)
		Expect(err).Should(BeNil())
		alpha, err := m1.Decrypt(encMessage)
		Expect(err).Should(BeNil())

		// r = k1a1 + k1a2
		r, err := m1.GetResult([]*big.Int{alpha}, []*big.Int{beta})
		// alpha = k1a2 - beta
		k1a2 := new(big.Int).Mul(m1.k, m2.a)
		exp := new(big.Int).Add(k1a2, m1.GetAK())
		exp = new(big.Int).Mod(exp, m1.fieldOrder)
		Expect(err).Should(BeNil())
		Expect(r).Should(Equal(exp))
	},
		Entry("CL", c1, c2),
		Entry("paillier", p1, p2),
	)
})
