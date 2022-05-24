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

	"github.com/btcsuite/btcd/btcec/v2"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Schnorr (Sigma protocol)", func() {
	var (
		R = pt.ScalarBaseMult(btcec.S256(), big.NewInt(982374))
		H = pt.ScalarBaseMult(btcec.S256(), big.NewInt(234111111))
		G = pt.NewBase(btcec.S256())
	)

	DescribeTable("should be ok", func(sigma, ell *big.Int) {
		S, T := generateSAndT(sigma, ell, R, G, H)
		msg, err := NewConsistencyTwoPoints(sigma, ell, R, H, S, T)
		Expect(err).Should(BeNil())
		err = msg.Verify(R, H, S, T)
		Expect(err).Should(BeNil())
	},
		Entry("sigma, ell", big.NewInt(100), big.NewInt(200)),
		Entry("sigma, ell", big.NewInt(8177), big.NewInt(9999)),
	)

	Context("NewConsistencyTwoPoints", func() {
		It("sigma is out of range", func() {
			sigma := btcec.S256().Params().N
			ell := big.NewInt(3)
			S, T := generateSAndT(sigma, ell, R, G, H)
			p, err := NewConsistencyTwoPoints(sigma, ell, R, H, S, T)
			Expect(err).Should(Equal(utils.ErrNotInRange))
			Expect(p).Should(BeNil())
		})

		It("ell is out of range", func() {
			sigma := big.NewInt(3)
			ell := btcec.S256().Params().N
			S, T := generateSAndT(sigma, ell, R, G, H)
			p, err := NewConsistencyTwoPoints(sigma, ell, R, H, S, T)
			Expect(err).Should(Equal(utils.ErrNotInRange))
			Expect(p).Should(BeNil())
		})
	})

	Context("Verify", func() {
		var (
			msg *ConsistencyTwoPointsMessage
			S   *pt.ECPoint
			T   *pt.ECPoint

			falsePoint *pt.ECPoint
		)
		BeforeEach(func() {
			S, T = generateSAndT(big.NewInt(100), big.NewInt(200), R, G, H)
			var err error
			msg, err = NewConsistencyTwoPoints(big.NewInt(100), big.NewInt(200), R, H, S, T)
			Expect(err).Should(BeNil())
			Expect(msg).ShouldNot(BeNil())
			falsePoint = pt.NewBase(elliptic.P521())
		})

		It("u is out of range", func() {
			msg.U = btcec.S256().Params().N.Bytes()
			Expect(msg.Verify(R, H, S, T)).ShouldNot(BeNil())
		})

		It("t is out of range", func() {
			msg.T = btcec.S256().Params().N.Bytes()
			Expect(msg.Verify(R, H, S, T)).ShouldNot(BeNil())
		})

		It("A is nil", func() {
			msg.A = nil
			Expect(msg.Verify(R, H, S, T)).ShouldNot(BeNil())
		})

		It("B is nil", func() {
			msg.B = nil
			Expect(msg.Verify(R, H, S, T)).ShouldNot(BeNil())
		})

		It("Different curve: R is falsePoint", func() {
			Expect(msg.Verify(falsePoint, H, S, T)).ShouldNot(BeNil())
		})

		It("Different curve: H is falsePoint", func() {
			Expect(msg.Verify(R, falsePoint, S, T)).ShouldNot(BeNil())
		})

		It("Different curve: S is falsePoint", func() {
			Expect(msg.Verify(R, H, falsePoint, T)).ShouldNot(BeNil())
		})

		It("Different curve: T is falsePoint", func() {
			Expect(msg.Verify(R, H, S, falsePoint)).ShouldNot(BeNil())
		})

		It("A is falsePoint", func() {
			msg.A, _ = falsePoint.ToEcPointMessage()
			Expect(msg.Verify(R, H, S, T)).ShouldNot(BeNil())
		})

		It("B is falsePoint", func() {
			msg.B, _ = falsePoint.ToEcPointMessage()
			Expect(msg.Verify(R, H, S, T)).ShouldNot(BeNil())
		})

		It("S is wrong", func() {
			wrongS := pt.NewBase(btcec.S256())
			Expect(msg.Verify(R, H, wrongS, T)).ShouldNot(BeNil())
		})

		It("T is wrong", func() {
			wrongT := R.Copy()
			Expect(msg.Verify(R, H, S, wrongT)).ShouldNot(BeNil())
		})
	})
})

func generateSAndT(sigma, ell *big.Int, R, G, H *pt.ECPoint) (*pt.ECPoint, *pt.ECPoint) {
	S := R.ScalarMult(sigma)
	T := G.ScalarMult(sigma)
	ellH := H.ScalarMult(ell)
	T, _ = T.Add(ellH)
	return S, T
}
