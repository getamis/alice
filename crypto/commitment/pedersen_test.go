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

package commitment

import (
	"crypto/elliptic"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	bkhoff "github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pedersen commitment test", func() {
	DescribeTable("buildPedersenCommitMessage()", func(curve elliptic.Curve) {
		N := curve.Params().N
		hiddingPoint := pt.ScalarBaseMult(curve, big.NewInt(15))
		secrets, err := polynomial.NewPolynomial(N, []*big.Int{big.NewInt(0), big.NewInt(10), big.NewInt(100)})
		Expect(err).Should(BeNil())
		salts, err := polynomial.NewPolynomial(N, []*big.Int{big.NewInt(1), big.NewInt(11), big.NewInt(111)})
		Expect(err).Should(BeNil())
		got, err := buildPedersenCommitMessage(hiddingPoint, secrets, salts)
		Expect(err).Should(BeNil())
		expected := &PointCommitmentMessage{
			Points: make([]*pt.EcPointMessage, 3),
		}
		expected.Points[0], _ = pt.ScalarBaseMult(curve, big.NewInt(15)).ToEcPointMessage()
		expected.Points[1], _ = pt.ScalarBaseMult(curve, big.NewInt(175)).ToEcPointMessage()
		expected.Points[2], _ = pt.ScalarBaseMult(curve, big.NewInt(1765)).ToEcPointMessage()
		Expect(got).Should(Equal(expected))
	},
		Entry("P224", elliptic.P224()),
		Entry("P256", elliptic.P256()),
		Entry("P384", elliptic.P384()),
		Entry("S256", btcec.S256()),
	)

	Context("buildPedersenCommitMessage()", func() {
		curve := elliptic.P256()
		N := curve.Params().N
		It("different length", func() {
			hiddingPoint := pt.ScalarBaseMult(curve, big.NewInt(15))
			secrets, err := polynomial.NewPolynomial(N, []*big.Int{big.NewInt(0), big.NewInt(10), big.NewInt(100), big.NewInt(1111)})
			Expect(err).Should(BeNil())
			salts, err := polynomial.NewPolynomial(N, []*big.Int{big.NewInt(1), big.NewInt(11), big.NewInt(111)})
			Expect(err).Should(BeNil())
			got, err := buildPedersenCommitMessage(hiddingPoint, secrets, salts)
			Expect(err).Should(Equal(ErrDifferentLength))
			Expect(got).Should(BeNil())
		})
	})

	DescribeTable("should be ok", func(x, hValue *big.Int, rank, threshold uint32, curve elliptic.Curve) {
		N := curve.Params().N
		degree := threshold - 1
		hiddingPoint := pt.ScalarBaseMult(curve, hValue)

		By("set P1 pointCommitment")
		secret1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		salt1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		pc1, err := NewPedersenCommitmenter(threshold, hiddingPoint, secret1, salt1)
		Expect(err).Should(BeNil())

		By("Verify P1 commitment and send values")
		bk := bkhoff.NewBkParameter(x, rank)
		verifyMsg := pc1.GetVerifyMessage(bk)
		err = verifyMsg.Verify(pc1.GetCommitmentMessage(), hiddingPoint, bk, degree)
		Expect(err).Should(BeNil())
	},
		Entry("should be OK",
			big.NewInt(225), big.NewInt(113), uint32(1), uint32(3), elliptic.P224()),
		Entry("should be OK",
			big.NewInt(2290), big.NewInt(112), uint32(0), uint32(2), elliptic.P256()),
		Entry("zero point case",
			big.NewInt(2290), big.NewInt(112), uint32(2), uint32(2), elliptic.P224()),
		Entry("should be OK",
			big.NewInt(2291), big.NewInt(114), uint32(2), uint32(5), elliptic.P256()),
	)

	DescribeTable("failed to verify due to wrong rank", func(x, hValue *big.Int, rank, threshold uint32, curve elliptic.Curve) {
		N := curve.Params().N
		degree := threshold - 1
		hiddingPoint := pt.ScalarBaseMult(curve, hValue)

		By("set P1 pointCommitment")
		secret1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		salt1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		pc1, err := NewPedersenCommitmenter(threshold, hiddingPoint, secret1, salt1)
		Expect(err).Should(BeNil())

		By("Verify P1 commitment and send values")
		wrongBk := bkhoff.NewBkParameter(x, rank+2)
		verifyMsg := pc1.GetVerifyMessage(wrongBk)
		bk := bkhoff.NewBkParameter(x, rank)
		err = verifyMsg.Verify(pc1.GetCommitmentMessage(), hiddingPoint, bk, degree)
		Expect(err).Should(Equal(ErrFailedVerify))
	},
		Entry("case #0",
			big.NewInt(225), big.NewInt(113), uint32(1), uint32(3), elliptic.P224()),
		Entry("case #1",
			big.NewInt(2290), big.NewInt(112), uint32(0), uint32(2), elliptic.P256()),
		Entry("case #2",
			big.NewInt(2291), big.NewInt(114), uint32(2), uint32(5), elliptic.P256()),
	)

	DescribeTable("failed to verify due to wrong x", func(x, hValue *big.Int, rank, threshold uint32, curve elliptic.Curve) {
		N := curve.Params().N
		degree := threshold - 1
		hiddingPoint := pt.ScalarBaseMult(curve, hValue)

		By("set P1 pointCommitment")
		secret1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		salt1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		pc1, err := NewPedersenCommitmenter(threshold, hiddingPoint, secret1, salt1)
		Expect(err).Should(BeNil())

		By("Verify P1 commitment and send values")
		wrongBk := bkhoff.NewBkParameter(new(big.Int).Add(x, big.NewInt(1)), rank)
		verifyMsg := pc1.GetVerifyMessage(wrongBk)
		bk := bkhoff.NewBkParameter(x, rank)
		err = verifyMsg.Verify(pc1.GetCommitmentMessage(), hiddingPoint, bk, degree)
		Expect(err).Should(Equal(ErrFailedVerify))
	},
		Entry("case #0",
			big.NewInt(225), big.NewInt(113), uint32(1), uint32(3), elliptic.P224()),
		Entry("case #1",
			big.NewInt(2290), big.NewInt(112), uint32(0), uint32(2), elliptic.P256()),
		Entry("case #2",
			big.NewInt(2291), big.NewInt(114), uint32(2), uint32(5), elliptic.P256()),
	)
})
