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

	bkhoff "github.com/aisuosuo/alice/crypto/birkhoffinterpolation"
	pt "github.com/aisuosuo/alice/crypto/ecpointgrouplaw"
	"github.com/aisuosuo/alice/crypto/polynomial"
	"github.com/btcsuite/btcd/btcec"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Feldman commitment test", func() {
	DescribeTable("buildFeldmanCommitMessage()", func(curve elliptic.Curve) {
		N := curve.Params().N
		secrets, err := polynomial.NewPolynomial(N, []*big.Int{big.NewInt(0), big.NewInt(10), big.NewInt(100)})
		Expect(err).Should(BeNil())
		got, err := buildFeldmanCommitMessage(curve, secrets)
		Expect(err).Should(BeNil())
		expected := &PointCommitmentMessage{
			Points: make([]*pt.EcPointMessage, 3),
		}
		expected.Points[0], _ = pt.ScalarBaseMult(curve, big.NewInt(0)).ToEcPointMessage()
		expected.Points[1], _ = pt.ScalarBaseMult(curve, big.NewInt(10)).ToEcPointMessage()
		expected.Points[2], _ = pt.ScalarBaseMult(curve, big.NewInt(100)).ToEcPointMessage()
		Expect(got).Should(Equal(expected))
	},
		Entry("P224", elliptic.P224()),
		Entry("P256", elliptic.P256()),
		Entry("P384", elliptic.P384()),
		Entry("S256", btcec.S256()),
	)

	DescribeTable("should be ok", func(x *big.Int, rank, threshold uint32, curve elliptic.Curve) {
		N := curve.Params().N
		degree := threshold - 1

		By("set P1 pointCommitment")
		secret1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		pc1, err := NewFeldmanCommitmenter(curve, secret1)
		Expect(err).Should(BeNil())

		By("Verify P1 commitment and send values")
		bk := bkhoff.NewBkParameter(x, rank)
		verifyMsg := pc1.GetVerifyMessage(bk)
		err = verifyMsg.Verify(pc1.GetCommitmentMessage(), bk, degree)
		Expect(err).Should(BeNil())
	},
		Entry("should be OK",
			big.NewInt(225), uint32(1), uint32(3), elliptic.P224()),
		Entry("should be OK",
			big.NewInt(2290), uint32(0), uint32(2), elliptic.P256()),
		Entry("zero point case",
			big.NewInt(2290), uint32(2), uint32(2), elliptic.P224()),
		Entry("should be OK",
			big.NewInt(2291), uint32(2), uint32(5), elliptic.P256()),
	)

	DescribeTable("failed to verify due to wrong rank", func(x *big.Int, rank, threshold uint32, curve elliptic.Curve) {
		N := curve.Params().N
		degree := threshold - 1

		By("set P1 pointCommitment")
		secret1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		pc1, err := NewFeldmanCommitmenter(curve, secret1)
		Expect(err).Should(BeNil())

		By("Verify P1 commitment and send values")
		wrongBk := bkhoff.NewBkParameter(x, rank+2)
		verifyMsg := pc1.GetVerifyMessage(wrongBk)
		bk := bkhoff.NewBkParameter(x, rank)
		err = verifyMsg.Verify(pc1.GetCommitmentMessage(), bk, degree)
		Expect(err).Should(Equal(ErrFailedVerify))
	},
		Entry("case #0",
			big.NewInt(225), uint32(1), uint32(3), elliptic.P224()),
		Entry("case #1",
			big.NewInt(2290), uint32(0), uint32(2), elliptic.P256()),
		Entry("case #2",
			big.NewInt(2291), uint32(2), uint32(5), elliptic.P256()),
	)

	DescribeTable("failed to verify due to wrong x", func(x *big.Int, rank, threshold uint32, curve elliptic.Curve) {
		N := curve.Params().N
		degree := threshold - 1

		By("set P1 pointCommitment")
		secret1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		pc1, err := NewFeldmanCommitmenter(curve, secret1)
		Expect(err).Should(BeNil())

		By("Verify P1 commitment and send values")
		wrongBk := bkhoff.NewBkParameter(new(big.Int).Add(x, big.NewInt(1)), rank)
		verifyMsg := pc1.GetVerifyMessage(wrongBk)
		bk := bkhoff.NewBkParameter(x, rank)
		err = verifyMsg.Verify(pc1.GetCommitmentMessage(), bk, degree)
		Expect(err).Should(Equal(ErrFailedVerify))
	},
		Entry("case #0",
			big.NewInt(225), uint32(1), uint32(3), elliptic.P224()),
		Entry("case #1",
			big.NewInt(2290), uint32(0), uint32(2), elliptic.P256()),
		Entry("case #2",
			big.NewInt(2291), uint32(2), uint32(5), elliptic.P256()),
	)

	DescribeTable("invalid commitment message", func(x *big.Int, rank, threshold uint32, curve elliptic.Curve) {
		N := curve.Params().N
		degree := threshold - 1
		secrets, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		_, err = NewFeldmanCommitmenter(curve, secrets)
		Expect(err).Should(BeNil())

		By("set P1 pointCommitment")
		secret1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		pc1, err := NewFeldmanCommitmenter(curve, secret1)
		Expect(err).Should(BeNil())

		By("Verify P1 commitment and send values")
		bk := bkhoff.NewBkParameter(x, rank)
		verifyMsg := pc1.GetVerifyMessage(bk)
		err = verifyMsg.Verify(&PointCommitmentMessage{
			Points: []*pt.EcPointMessage{nil},
		}, bk, degree)
		Expect(err).Should(Equal(pt.ErrDifferentLength))
	},
		Entry("should be OK",
			big.NewInt(225), uint32(1), uint32(3), elliptic.P224()),
		Entry("should be OK",
			big.NewInt(2290), uint32(0), uint32(2), elliptic.P256()),
		Entry("zero point case",
			big.NewInt(2290), uint32(2), uint32(2), elliptic.P224()),
		Entry("should be OK",
			big.NewInt(2291), uint32(2), uint32(5), elliptic.P256()),
	)

	DescribeTable("empty points in commitment message", func(x *big.Int, rank, threshold uint32, curve elliptic.Curve) {
		N := curve.Params().N
		degree := threshold - 1

		By("set P1 pointCommitment")
		secret1, err := polynomial.RandomPolynomial(N, degree)
		Expect(err).Should(BeNil())
		pc1, err := NewFeldmanCommitmenter(curve, secret1)
		Expect(err).Should(BeNil())

		By("Verify P1 commitment and send values")
		bk := bkhoff.NewBkParameter(x, rank)
		verifyMsg := pc1.GetVerifyMessage(bk)
		err = verifyMsg.Verify(&PointCommitmentMessage{
			Points: []*pt.EcPointMessage{},
		}, bk, degree)
		Expect(err).Should(Equal(pt.ErrDifferentLength))
	},
		Entry("should be OK",
			big.NewInt(225), uint32(1), uint32(3), elliptic.P224()),
		Entry("should be OK",
			big.NewInt(2290), uint32(0), uint32(2), elliptic.P256()),
		Entry("zero point case",
			big.NewInt(2290), uint32(2), uint32(2), elliptic.P224()),
		Entry("should be OK",
			big.NewInt(2291), uint32(2), uint32(5), elliptic.P256()),
	)
})
