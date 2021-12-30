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
	"crypto/elliptic"
	"math/big"

	pt "github.com/aisuosuo/alice/crypto/ecpointgrouplaw"
	"github.com/btcsuite/btcd/btcec"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Schnorr (Sigma protocol)", func() {
	var (
		a1 = big.NewInt(200)
		a2 = big.NewInt(39818)

		R = pt.ScalarBaseMult(btcec.S256(), big.NewInt(0))
	)

	DescribeTable("should be ok", func(R *pt.ECPoint) {
		p, err := NewSchorrMessage(a1, a2, R)
		Expect(err).Should(BeNil())
		Expect(p.Verify(R)).Should(BeNil())
	},
		Entry("Curve: P256 #1", pt.ScalarBaseMult(elliptic.P256(), big.NewInt(0))),
		Entry("Curve: P256 #2", pt.ScalarBaseMult(elliptic.P256(), big.NewInt(55))),
		Entry("Curve: S256 #1", pt.ScalarBaseMult(btcec.S256(), big.NewInt(0))),
		Entry("Curve: S256 #2", pt.ScalarBaseMult(btcec.S256(), big.NewInt(123))),
	)

	DescribeTable("NewBaseSchorrMessage", func(curve elliptic.Curve) {
		p, err := NewBaseSchorrMessage(curve, a1)
		Expect(err).Should(BeNil())
		Expect(p.Verify(pt.NewBase(curve))).Should(BeNil())
	},
		Entry("Curve: P256", elliptic.P256()),
		Entry("Curve: S256", btcec.S256()),
	)

	Context("NewSchorrMessage", func() {
		It("invalid point message", func() {
			p, err := NewSchorrMessage(a1, a2, &pt.ECPoint{})
			Expect(err).ShouldNot(BeNil())
			Expect(p).Should(BeNil())
		})

		It("a1 is out of range", func() {
			wrongA1 := btcec.S256().Params().N
			p, err := NewSchorrMessage(wrongA1, a2, R)
			Expect(err).ShouldNot(BeNil())
			Expect(p).Should(BeNil())
		})

		It("a2 is out of range", func() {
			wrongA2 := btcec.S256().Params().N
			p, err := NewSchorrMessage(a1, wrongA2, R)
			Expect(err).ShouldNot(BeNil())
			Expect(p).Should(BeNil())
		})
	})

	Context("Verify", func() {
		var (
			msg *SchnorrProofMessage
		)
		BeforeEach(func() {
			var err error
			msg, err = NewSchorrMessage(a1, a2, R)
			Expect(err).Should(BeNil())
			Expect(msg).ShouldNot(BeNil())
		})

		It("u is out of range", func() {
			msg.U = btcec.S256().Params().N.Bytes()
			Expect(msg.Verify(R)).ShouldNot(BeNil())
		})

		It("t is out of range", func() {
			msg.T = btcec.S256().Params().N.Bytes()
			Expect(msg.Verify(R)).ShouldNot(BeNil())
		})

		It("V is invalid point message", func() {
			msg.V = nil
			Expect(msg.Verify(R)).ShouldNot(BeNil())
		})

		It("Alpha is invalid point message", func() {
			msg.Alpha = nil
			Expect(msg.Verify(R)).ShouldNot(BeNil())
		})

		It("Different curves", func() {
			wrongR := pt.ScalarBaseMult(elliptic.P256(), big.NewInt(0))
			Expect(msg.Verify(wrongR)).Should(Equal(ErrDifferentCurves))
		})

		It("Failed to verify", func() {
			msg.Salt = []byte{1, 2, 3}
			Expect(msg.Verify(R)).Should(Equal(ErrVerifyFailure))
		})
	})
})
