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
package signer

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/elliptic"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func TestSigner(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Signer Suite")
}

var _ = Describe("Signer", func() {
	var (
		curve = elliptic.Secp256k1()
		msg   = []byte{1, 2, 3}
	)

	DescribeTable("NewSigner()", func(ss [][]*big.Int, gScale *big.Int) {
		// new peer managers and dkgs
		expPublic := ecpointgrouplaw.ScalarBaseMult(curve, gScale)
		threshold := len(ss)
		signers, listeners := newSigners(curve, expPublic, ss, msg)
		doneChs := make([]chan struct{}, threshold)
		i := 0
		for _, l := range listeners {
			doneChs[i] = make(chan struct{})
			doneCh := doneChs[i]
			l.On("OnStateChanged", types.StateInit, types.StateDone).Run(func(args mock.Arguments) {
				close(doneCh)
			}).Once()
			i++
		}

		for _, s := range signers {
			s.Start()
		}

		for i := 0; i < threshold; i++ {
			<-doneChs[i]
		}

		// Build public key
		var r, s *big.Int
		for _, signer := range signers {
			signer.Stop()
			result, err := signer.GetResult()
			Expect(err).Should(BeNil())
			// All R and S should be the same
			if r != nil {
				Expect(r).Should(Equal(result.R))
				Expect(s).Should(Equal(result.S))
			} else {
				r = result.R
				s = result.S
			}
		}
		ecdsaPublicKey := &ecdsa.PublicKey{
			Curve: expPublic.GetCurve(),
			X:     expPublic.GetX(),
			Y:     expPublic.GetY(),
		}
		Expect(ecdsa.Verify(ecdsaPublicKey, msg, r, s)).Should(BeTrue())

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("(shareX, shareY, rank):(1,3,0),(10,111,0),(20,421,0)", [][]*big.Int{
			{big.NewInt(1), big.NewInt(3), big.NewInt(0)},
			{big.NewInt(10), big.NewInt(111), big.NewInt(0)},
			{big.NewInt(20), big.NewInt(421), big.NewInt(0)},
		}, big.NewInt(1)),
		Entry("(shareX, shareY, rank):(108,4517821,0),(344,35822,1),(756,46,2)", [][]*big.Int{
			{big.NewInt(108), big.NewInt(4517821), big.NewInt(0)},
			{big.NewInt(344), big.NewInt(35822), big.NewInt(1)},
			{big.NewInt(756), big.NewInt(46), big.NewInt(2)},
		}, big.NewInt(2089765)),
		Entry("(shareX, shareY, rank):(53,2816277,0),(24,48052,1),(96,9221170,0)", [][]*big.Int{
			{big.NewInt(53), big.NewInt(2816277), big.NewInt(0)},
			{big.NewInt(24), big.NewInt(48052), big.NewInt(1)},
			{big.NewInt(96), big.NewInt(9221170), big.NewInt(0)},
		}, big.NewInt(4786)),
		Entry("(shareX, shareY, rank):(756,1408164810,0),(59887,285957312,1),(817291849,3901751343900,1)", [][]*big.Int{
			{big.NewInt(756), big.NewInt(1408164810), big.NewInt(0)},
			{big.NewInt(59887), big.NewInt(285957312), big.NewInt(1)},
			{big.NewInt(817291849), big.NewInt(3901751343900), big.NewInt(1)},
		}, big.NewInt(987234)),
		Entry("(shareX, shareY, rank):(999,1990866633,0),(877,1535141367,1),(6542,85090458377,1)", [][]*big.Int{
			{big.NewInt(999), big.NewInt(1990866633), big.NewInt(0)},
			{big.NewInt(877), big.NewInt(1535141367), big.NewInt(0)},
			{big.NewInt(6542), big.NewInt(85090458377), big.NewInt(0)},
		}, big.NewInt(5487)),
		Entry("(shareX, shareY, rank):(1094,591493497,0),(59887,58337825,1),(6542,20894113809,0)", [][]*big.Int{
			{big.NewInt(1094), big.NewInt(591493497), big.NewInt(0)},
			{big.NewInt(59887), big.NewInt(58337825), big.NewInt(1)},
			{big.NewInt(6542), big.NewInt(20894113809), big.NewInt(0)},
		}, big.NewInt(5987)),
		Entry("(shareX, shareY, rank):(404,1279853690,0),(99555,1548484036,1),(64444,15554,2)", [][]*big.Int{
			{big.NewInt(404), big.NewInt(1279853690), big.NewInt(0)},
			{big.NewInt(99555), big.NewInt(1548484036), big.NewInt(1)},
			{big.NewInt(64444), big.NewInt(15554), big.NewInt(2)},
		}, big.NewInt(8274194)),
	)
})

func newSigners(curve elliptic.Curve, expPublic *ecpointgrouplaw.ECPoint, ss [][]*big.Int, msg []byte) (map[string]*Signer, map[string]*mocks.StateChangedListener) {
	threshold := len(ss)
	signers := make(map[string]*Signer, threshold)
	signersMain := make(map[string]types.MessageMain, threshold)
	peerManagers := make([]types.PeerManager, threshold)
	listeners := make(map[string]*mocks.StateChangedListener, threshold)

	bks := make(map[string]*birkhoffinterpolation.BkParameter, threshold)
	for i := 0; i < threshold; i++ {
		bks[tss.GetTestID(i)] = birkhoffinterpolation.NewBkParameter(ss[i][0], uint32(ss[i][2].Uint64()))
	}

	for i := 0; i < threshold; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, threshold)
		pm.Set(signersMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		homo, err := paillier.NewPaillier(2048)
		Expect(err).Should(BeNil())
		signers[id], err = NewSigner(peerManagers[i], expPublic, homo, ss[i][1], bks, msg, listeners[id])
		Expect(err).Should(BeNil())
		signersMain[id] = signers[id]
		r, err := signers[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return signers, listeners
}
