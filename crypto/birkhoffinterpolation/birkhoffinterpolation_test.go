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
package birkhoffinterpolation

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/matrix"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var (
	secp256k1 = elliptic.NewSecp256k1()
)

func TestBirkhoffinterpolation(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Birkhoffinterpolation Suite")
}

var _ = Describe("Birkhoff Interpolation", func() {
	var (
		bigNumber   = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
		bigPrime, _ = new(big.Int).SetString(bigNumber, 10)
	)

	Context("getLinearEquationCoefficientMatrix()", func() {
		It("should be ok", func() {
			ps := make(BkParameters, 5)
			ps[0] = NewBkParameter(big.NewInt(1), 0)
			ps[1] = NewBkParameter(big.NewInt(2), 1)
			ps[2] = NewBkParameter(big.NewInt(3), 2)
			ps[3] = NewBkParameter(big.NewInt(4), 3)
			ps[4] = NewBkParameter(big.NewInt(5), 4)
			got, err := ps.getLinearEquationCoefficientMatrix(4, bigPrime)
			Expect(err).Should(BeNil())

			expectedMatrix := [][]*big.Int{
				{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(1), big.NewInt(4), big.NewInt(12)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(2), big.NewInt(18)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(6)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			}
			expected, err := matrix.NewMatrix(bigPrime, expectedMatrix)
			Expect(got).Should(Equal(expected))
			Expect(err).Should(BeNil())
		})
	})

	It("Getter func", func() {
		x := big.NewInt(1)
		rank := uint32(0)
		bk := NewBkParameter(x, rank)
		Expect(bk.GetX()).Should(Equal(x))
		Expect(bk.GetRank()).Should(Equal(rank))
		Expect(bk.String()).Should(Equal("(x, rank) = (1, 0)"))
	})

	DescribeTable("VerifyEnoughRankCanRecoverSecret func", func(ps BkParameters) {
		err := ps.CheckValid(uint32(3), bigPrime)
		Expect(err).Should(BeNil())
	},
		Entry("BK:(x,rank):(1,0),(2,1),(3,2),(5,4),(4,3)",
			[]*BkParameter{NewBkParameter(big.NewInt(1), 0), NewBkParameter(big.NewInt(2), 1),
				NewBkParameter(big.NewInt(3), 2), NewBkParameter(big.NewInt(5), 4), NewBkParameter(big.NewInt(4), 3)},
		),
		Entry("BK:(x,rank):(1,0),(2,3),(3,0),(5,0),(4,0)",
			[]*BkParameter{NewBkParameter(big.NewInt(1), 0), NewBkParameter(big.NewInt(2), 3),
				NewBkParameter(big.NewInt(3), 0), NewBkParameter(big.NewInt(5), 0), NewBkParameter(big.NewInt(4), 0)},
		),
		Entry("BK:(x,rank):(1,0),(2,0),(3,0),(5,0),(4,0)",
			[]*BkParameter{NewBkParameter(big.NewInt(1), 0), NewBkParameter(big.NewInt(2), 0),
				NewBkParameter(big.NewInt(3), 0), NewBkParameter(big.NewInt(5), 0), NewBkParameter(big.NewInt(4), 0)},
		),
		Entry("BK:(x,rank):(1,1),(2,1),(3,1),(5,0),(4,0)",
			[]*BkParameter{NewBkParameter(big.NewInt(1), 1), NewBkParameter(big.NewInt(2), 1),
				NewBkParameter(big.NewInt(3), 1), NewBkParameter(big.NewInt(5), 0), NewBkParameter(big.NewInt(4), 0)},
		),
		Entry("BK:(x,rank):(1,1),(2,1),(3,1),(5,1),(4,0)",
			[]*BkParameter{NewBkParameter(big.NewInt(1), 1), NewBkParameter(big.NewInt(2), 1),
				NewBkParameter(big.NewInt(3), 1), NewBkParameter(big.NewInt(5), 1), NewBkParameter(big.NewInt(4), 0)},
		),
	)

	It("duplicate Bk", func() {
		ps := make(BkParameters, 5)
		ps[0] = NewBkParameter(big.NewInt(1), 0)
		ps[1] = NewBkParameter(big.NewInt(2), 1)
		ps[2] = NewBkParameter(big.NewInt(3), 2)
		ps[3] = NewBkParameter(big.NewInt(1), 0)
		ps[4] = NewBkParameter(big.NewInt(5), 4)
		err := ps.CheckValid(uint32(3), bigPrime)
		Expect(err).Should(Equal(ErrInvalidBks))
	})

	// The problem is that (1,0) and (2,1) and (3,0) can not recover secret.
	It("Expect no valid bks", func() {
		ps := make(BkParameters, 5)
		ps[3] = NewBkParameter(big.NewInt(4), 2)
		ps[4] = NewBkParameter(big.NewInt(5), 2)
		ps[0] = NewBkParameter(big.NewInt(1), 2)
		ps[1] = NewBkParameter(big.NewInt(2), 2)
		ps[2] = NewBkParameter(big.NewInt(3), 2)
		err := ps.CheckValid(uint32(3), bigPrime)
		Expect(err).Should(Equal(ErrNoValidBks))
	})

	// The problem is that (1,0) and (2,1) and (3,0) can not recover secret.
	It("Expect Enough Rank but not have", func() {
		ps := make(BkParameters, 5)
		ps[3] = NewBkParameter(big.NewInt(4), 0)
		ps[4] = NewBkParameter(big.NewInt(5), 0)
		ps[0] = NewBkParameter(big.NewInt(1), 0)
		ps[1] = NewBkParameter(big.NewInt(2), 1)
		ps[2] = NewBkParameter(big.NewInt(3), 0)
		err := ps.CheckValid(uint32(3), bigPrime)
		Expect(err).Should(Equal(ErrInvalidBks))
	})

	Context("ComputeBkCoefficient()", func() {
		It("should be ok", func() {
			ps := make(BkParameters, 4)
			ps[0] = NewBkParameter(big.NewInt(1), 0)
			ps[1] = NewBkParameter(big.NewInt(2), 1)
			ps[2] = NewBkParameter(big.NewInt(3), 2)
			ps[3] = NewBkParameter(big.NewInt(4), 3)
			expectedStrs := []string{
				"1",
				"115792089237316195423570985008687907852837564279074904382605163141518161494336",
				"57896044618658097711785492504343953926418782139537452191302581570759080747170",
				"0",
			}
			expected := make([]*big.Int, len(expectedStrs))
			for i, s := range expectedStrs {
				expected[i], _ = new(big.Int).SetString(s, 10)
			}
			got, err := ps.ComputeBkCoefficient(3, bigPrime)
			Expect(err).Should(BeNil())
			Expect(got).Should(Equal(expected))
		})

		It("invalid field order", func() {
			ps := make(BkParameters, 4)
			ps[0] = NewBkParameter(big.NewInt(1), 0)
			ps[1] = NewBkParameter(big.NewInt(2), 1)
			ps[2] = NewBkParameter(big.NewInt(3), 2)
			ps[3] = NewBkParameter(big.NewInt(4), 3)
			got, err := ps.ComputeBkCoefficient(3, big.NewInt(2))
			Expect(err).Should(Equal(utils.ErrLessOrEqualBig2))
			Expect(got).Should(BeNil())
		})

		It("larger threshold", func() {
			ps := make(BkParameters, 2)
			ps[0] = NewBkParameter(big.NewInt(1), 0)
			ps[1] = NewBkParameter(big.NewInt(2), 1)
			got, err := ps.ComputeBkCoefficient(3, bigPrime)
			Expect(err).Should(Equal(ErrEqualOrLargerThreshold))
			Expect(got).Should(BeNil())
		})

		It("not invertible matrix #0", func() {
			ps := make(BkParameters, 4)
			ps[0] = NewBkParameter(big.NewInt(1), 2)
			ps[1] = NewBkParameter(big.NewInt(2), 2)
			ps[2] = NewBkParameter(big.NewInt(3), 3)
			ps[3] = NewBkParameter(big.NewInt(4), 0)
			got, err := ps.ComputeBkCoefficient(3, bigPrime)
			Expect(err).Should(Equal(matrix.ErrNotInvertableMatrix))
			Expect(got).Should(BeNil())
		})

		It("not invertible matrix #1", func() {
			ps := make(BkParameters, 5)
			ps[0] = NewBkParameter(big.NewInt(1), 2)
			ps[1] = NewBkParameter(big.NewInt(2), 2)
			ps[2] = NewBkParameter(big.NewInt(3), 3)
			ps[3] = NewBkParameter(big.NewInt(4), 1)
			ps[4] = NewBkParameter(big.NewInt(5), 4)
			got, err := ps.ComputeBkCoefficient(3, bigPrime)
			Expect(err).Should(Equal(matrix.ErrNotInvertableMatrix))
			Expect(got).Should(BeNil())
		})

		It("not invertible matrix #2 - two the same X", func() {
			ps := make(BkParameters, 5)
			ps[0] = NewBkParameter(big.NewInt(1), 1)
			ps[1] = NewBkParameter(big.NewInt(2), 3)
			ps[2] = NewBkParameter(big.NewInt(3), 3)
			ps[3] = NewBkParameter(big.NewInt(1), 1)
			ps[4] = NewBkParameter(big.NewInt(5), 3)
			got, err := ps.ComputeBkCoefficient(3, bigPrime)
			Expect(err).Should(Equal(matrix.ErrNotInvertableMatrix))
			Expect(got).Should(BeNil())
		})
	})

	DescribeTable("GetAddShareFractionalValue()", func(newBK *BkParameter, expected string, ownIndex, threshold int) {
		ps := make(BkParameters, 3)
		ps[0] = NewBkParameter(big.NewInt(1), 0)
		ps[1] = NewBkParameter(big.NewInt(2), 1)
		ps[2] = NewBkParameter(big.NewInt(5), 0)

		got, err := ps.GetAddShareCoefficient(ps[ownIndex], newBK, bigPrime, 3)
		Expect(err).Should(BeNil())
		result, _ := new(big.Int).SetString(expected, 10)
		Expect(got.Cmp(result) == 0).Should(BeTrue())
	},
		Entry("BK : (6,0), ownIndex = 0",
			NewBkParameter(big.NewInt(6), 0), "101318078082651670995624611882601919371232868744190541334779517748828391307544", 0, 3,
		),
		Entry("BK : (6,0), ownIndex = 1",
			NewBkParameter(big.NewInt(6), 0), "57896044618658097711785492504343953926418782139537452191302581570759080747166", 1, 3,
		),
		Entry("BK : (6,0), ownIndex = 2",
			NewBkParameter(big.NewInt(6), 0), "14474011154664524427946373126085988481604695534884363047825645392689770186794", 2, 3,
		),
		Entry("BK : (6,1), ownIndex = 0",
			NewBkParameter(big.NewInt(6), 1), "115792089237316195423570985008687907852837564279074904382605163141518161494336", 0, 3,
		),
		Entry("BK : (6,1), ownIndex = 1",
			NewBkParameter(big.NewInt(6), 1), "115792089237316195423570985008687907852837564279074904382605163141518161494334", 1, 3,
		),
		Entry("BK : (6,1), ownIndex = 2",
			NewBkParameter(big.NewInt(6), 1), "1", 2, 3,
		),
		Entry("BK : (6,2), ownIndex = 0",
			NewBkParameter(big.NewInt(6), 2), "28948022309329048855892746252171976963209391069768726095651290785379540373584", 0, 3,
		),
		Entry("BK : (6,2), ownIndex = 1",
			NewBkParameter(big.NewInt(6), 2), "115792089237316195423570985008687907852837564279074904382605163141518161494336", 1, 3,
		),
		Entry("BK : (6,2), ownIndex = 2",
			NewBkParameter(big.NewInt(6), 2), "86844066927987146567678238756515930889628173209306178286953872356138621120753", 2, 3,
		),
	)

	It("getIndexOfBK(): can not find own Bk", func() {
		ps := make(BkParameters, 3)
		ps[0] = NewBkParameter(big.NewInt(1), 0)
		ps[1] = NewBkParameter(big.NewInt(2), 1)
		ps[2] = NewBkParameter(big.NewInt(5), 0)
		find := NewBkParameter(big.NewInt(5), 4)

		got, err := ps.getIndexOfBK(find)
		Expect(err).Should(Equal(ErrNoExistBk))
		Expect(got).Should(Equal(0))
	})

	Context("ValidatePublicKey", func() {
		var (
			err       error
			curve     elliptic.Curve
			threshold uint32
			poly      *polynomial.Polynomial
			expPubkey *ecpointgrouplaw.ECPoint
		)

		BeforeEach(func() {
			curve = secp256k1
			fieldOrder := curve.Params().N
			threshold = uint32(3)
			poly, err = polynomial.RandomPolynomial(fieldOrder, threshold-1)
			Expect(err).Should(BeNil())
			expPubkey = ecpointgrouplaw.ScalarBaseMult(curve, poly.Get(0))
		})

		It("should be ok", func() {
			xs := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(8)}
			ranks := []uint32{0, 0, 0}

			bks := make(BkParameters, threshold)
			sgs := make([]*pt.ECPoint, threshold)
			for i := 0; i < int(threshold); i++ {
				bks[i] = NewBkParameter(xs[i], ranks[i])
				newPoly := poly.Differentiate(ranks[i])
				si := newPoly.Evaluate(xs[i])
				sgs[i] = ecpointgrouplaw.ScalarBaseMult(curve, si)
			}
			err = bks.ValidatePublicKey(sgs, threshold, expPubkey)
			Expect(err).Should(BeNil())
		})

		It("failed to compute bk coefficient", func() {
			// duplicate bk
			xs := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(7)}
			ranks := []uint32{0, 0, 0}

			bks := make(BkParameters, threshold)
			sgs := make([]*pt.ECPoint, threshold)
			for i := 0; i < int(threshold); i++ {
				bks[i] = NewBkParameter(xs[i], ranks[i])
				newPoly := poly.Differentiate(ranks[i])
				si := newPoly.Evaluate(xs[i])
				sgs[i] = ecpointgrouplaw.ScalarBaseMult(curve, si)
			}
			err = bks.ValidatePublicKey(sgs, threshold, expPubkey)
			Expect(err).ShouldNot(BeNil())
		})

		It("failed to compute public key", func() {
			xs := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(8)}
			ranks := []uint32{0, 0, 0}

			bks := make(BkParameters, threshold)
			// different length between bks and sgs
			sgs := make([]*pt.ECPoint, threshold+1)
			for i := 0; i < int(threshold); i++ {
				bks[i] = NewBkParameter(xs[i], ranks[i])
				sgs[i] = ecpointgrouplaw.NewBase(curve)
			}
			err = bks.ValidatePublicKey(sgs, threshold, expPubkey)
			Expect(err).ShouldNot(BeNil())
		})

		It("failed with inconsistent public key", func() {
			xs := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(8)}
			ranks := []uint32{0, 0, 0}

			bks := make(BkParameters, threshold)
			sgs := make([]*pt.ECPoint, threshold)
			for i := 0; i < int(threshold); i++ {
				bks[i] = NewBkParameter(xs[i], ranks[i])
				// irrelevant siGs
				sgs[i] = ecpointgrouplaw.NewBase(curve)
			}
			err = bks.ValidatePublicKey(sgs, threshold, expPubkey)
			Expect(err).Should(Equal(ErrInconsistentPubKey))
		})
	})
})
