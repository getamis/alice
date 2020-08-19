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
package tss

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss/message/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestTSSUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TSS Utils Suite")
}

var _ = Describe("Utils", func() {
	Context("NewCommitterByPoint/GetPointFromHashCommitment", func() {
		It("should be ok", func() {
			p := pt.NewIdentity(btcec.S256())
			c, err := NewCommitterByPoint(p)
			Expect(err).Should(BeNil())
			Expect(c).ShouldNot(BeNil())

			got, err := GetPointFromHashCommitment(log.Discard(), c.GetCommitmentMessage(), c.GetDecommitmentMessage())
			Expect(err).Should(BeNil())
			Expect(got.Equal(p)).Should(BeTrue())
		})

		It("failed to new by empty point", func() {
			c, err := NewCommitterByPoint(&pt.ECPoint{})
			Expect(err).ShouldNot(BeNil())
			Expect(c).Should(BeNil())
		})

		It("not an ec point", func() {
			cm, err := commitment.NewHashCommitmenter([]byte{1, 2, 3})
			Expect(err).Should(BeNil())
			got, err := GetPointFromHashCommitment(log.Discard(), cm.GetCommitmentMessage(), cm.GetDecommitmentMessage())
			Expect(err).ShouldNot(BeNil())
			Expect(got).Should(BeNil())
		})
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
			curve = btcec.S256()
			fieldOrder := curve.Params().N
			threshold = uint32(3)
			poly, err = polynomial.RandomPolynomial(fieldOrder, threshold-1)
			Expect(err).Should(BeNil())
			expPubkey = ecpointgrouplaw.ScalarBaseMult(curve, poly.Get(0))
		})

		It("should be ok", func() {
			xs := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(8)}
			ranks := []uint32{0, 0, 0}

			bks := make(birkhoffinterpolation.BkParameters, threshold)
			sgs := make([]*pt.ECPoint, threshold)
			for i := 0; i < int(threshold); i++ {
				bks[i] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
				newPoly := poly.Differentiate(ranks[i])
				si := newPoly.Evaluate(xs[i])
				sgs[i] = ecpointgrouplaw.ScalarBaseMult(curve, si)
			}
			err = ValidatePublicKey(log.Discard(), bks, sgs, threshold, expPubkey)
			Expect(err).Should(BeNil())
		})

		It("failed to compute bk coefficient", func() {
			// duplicate bk
			xs := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(7)}
			ranks := []uint32{0, 0, 0}

			bks := make(birkhoffinterpolation.BkParameters, threshold)
			sgs := make([]*pt.ECPoint, threshold)
			for i := 0; i < int(threshold); i++ {
				bks[i] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
				newPoly := poly.Differentiate(ranks[i])
				si := newPoly.Evaluate(xs[i])
				sgs[i] = ecpointgrouplaw.ScalarBaseMult(curve, si)
			}
			err = ValidatePublicKey(log.Discard(), bks, sgs, threshold, expPubkey)
			Expect(err).ShouldNot(BeNil())
		})

		It("failed to compute public key", func() {
			xs := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(8)}
			ranks := []uint32{0, 0, 0}

			bks := make(birkhoffinterpolation.BkParameters, threshold)
			// different length between bks and sgs
			sgs := make([]*pt.ECPoint, threshold+1)
			for i := 0; i < int(threshold); i++ {
				bks[i] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
				sgs[i] = ecpointgrouplaw.NewBase(curve)
			}
			err = ValidatePublicKey(log.Discard(), bks, sgs, threshold, expPubkey)
			Expect(err).ShouldNot(BeNil())
		})

		It("failed with inconsistent public key", func() {
			xs := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(8)}
			ranks := []uint32{0, 0, 0}

			bks := make(birkhoffinterpolation.BkParameters, threshold)
			sgs := make([]*pt.ECPoint, threshold)
			for i := 0; i < int(threshold); i++ {
				bks[i] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
				// irrelevant siGs
				sgs[i] = ecpointgrouplaw.NewBase(curve)
			}
			err = ValidatePublicKey(log.Discard(), bks, sgs, threshold, expPubkey)
			Expect(err).Should(Equal(ErrInconsistentPubKey))
		})
	})

	Context("Broadcast", func() {
		var mockPeerManager *mocks.PeerManager

		BeforeEach(func() {
			mockPeerManager = new(mocks.PeerManager)
		})

		AfterEach(func() {
			mockPeerManager.AssertExpectations(GinkgoT())
		})

		It("should be ok", func() {
			peers := []string{
				"peer-1",
				"peer-2",
				"peer-3",
			}
			msg := "message"
			mockPeerManager.On("PeerIDs").Return(peers).Once()
			for _, id := range peers {
				mockPeerManager.On("MustSend", id, msg).Return(nil).Once()
			}
			Broadcast(mockPeerManager, msg)
		})
	})
})
