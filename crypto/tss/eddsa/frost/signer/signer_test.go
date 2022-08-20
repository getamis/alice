// Copyright © 2022 AMIS Technologies
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
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
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
		RumTime          = 20
		curve            = elliptic.Ed25519()
		poly, _          = polynomial.RandomPolynomial(curve.Params().N, 2)
		x1, _            = utils.RandomPositiveInt(curve.Params().N)
		x2, _            = utils.RandomPositiveInt(curve.Params().N)
		x3, _            = utils.RandomPositiveInt(curve.Params().N)
		share1           = poly.Evaluate(x1)
		share2           = poly.Evaluate(x2)
		share3           = poly.Evaluate(x3)
		secrertRandomKey = poly.Evaluate(big0)

		setx1, _     = new(big.Int).SetString("2254765913981550676205803762478430869696580688700958727495894224115312987764", 10)
		setx2, _     = new(big.Int).SetString("2117636074604900758115075527580492494720639688970891834155177238392086845382", 10)
		setx3, _     = new(big.Int).SetString("6414582964050248729324272790247195316284712038021768098875147472012178712076", 10)
		setShare1, _ = new(big.Int).SetString("3675788498585450082991846428007326057826754636663877385528274415846839676857", 10)
		setShare2, _ = new(big.Int).SetString("1522795425006476177538987458185716386773973361216994141828318603466392185301", 10)
		setShare3, _ = new(big.Int).SetString("4575846830523611786637644129807785488887694553004765055615792711279484061401", 10)
		xcoord1, _   = new(big.Int).SetString("13303072567237052328013834338380099174471808636153533034015575804719580433195", 10)
		ycoord1, _   = new(big.Int).SetString("16964052623936448625187294284159857344364737590067812676140890490183700057118", 10)
		pubKey, _    = ecpointgrouplaw.NewECPoint(curve, xcoord1, ycoord1)
	)

	DescribeTable("It should be OK", func(ss [][]*big.Int, privateKey *big.Int, pubKey *ecpointgrouplaw.ECPoint) {
		for i := 0; i < RumTime; i++ {
			expPublic := pubKey
			if privateKey != nil {
				expPublic = ecpointgrouplaw.ScalarBaseMult(curve, privateKey)
			}
			threshold := len(ss)
			message := []byte("8077818")
			signers, listeners := newSigners(curve, expPublic, ss, message)
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
			var R *ecpointgrouplaw.ECPoint
			var s *big.Int
			for _, signer := range signers {
				signer.Stop()
				result, err := signer.GetResult()
				Expect(err).Should(BeNil())
				// All R and S should be the same
				if R != nil {
					Expect(R.Equal(result.R)).Should(BeTrue())
					Expect(s).Should(Equal(result.S))
				} else {
					R = result.R
					s = result.S
				}
			}
			edwardPubKey := edwards.NewPublicKey(edwards.Edwards(), expPublic.GetX(), expPublic.GetY())
			test1 := ecpointEncoding(R)
			test2 := *test1
			r := new(big.Int).SetBytes(utils.ReverseByte(test2[:]))
			verifyResult := edwards.Verify(edwardPubKey, message, r, s)
			Expect(verifyResult).Should(BeTrue())
			if !verifyResult {
				break
			}
			for _, l := range listeners {
				l.AssertExpectations(GinkgoT())
			}
		}
	},
		Entry("(x-cooord, share, rank):f(x) = 2x+100", [][]*big.Int{
			{big.NewInt(1), big.NewInt(102), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(104), big.NewInt(0)},
			{big.NewInt(8), big.NewInt(116), big.NewInt(0)},
		}, big.NewInt(100), nil),
		Entry("(x-cooord, share, rank):f(x) = 2x+100", [][]*big.Int{
			{big.NewInt(1), big.NewInt(102), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(104), big.NewInt(0)},
		}, big.NewInt(100), nil),
		Entry("(x-cooord, share, rank):f(x) = x^2+5*x+1109", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1115), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(1123), big.NewInt(0)},
			{big.NewInt(50), big.NewInt(3859), big.NewInt(0)},
		}, big.NewInt(1109), nil),
		Entry("(x-cooord, share, rank):f(x) = x^2+3*x+5555", [][]*big.Int{
			{big.NewInt(1), big.NewInt(5559), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(5565), big.NewInt(0)},
			{big.NewInt(50), big.NewInt(103), big.NewInt(1)},
		}, big.NewInt(5555), nil),
		Entry("(x-cooord, share, rank):f(x) = 2*x^2+3*x+1111", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1116), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(4), big.NewInt(2)},
			{big.NewInt(50), big.NewInt(203), big.NewInt(1)},
		}, big.NewInt(1111), nil),
		Entry("(x-cooord, share, rank):f(x) = random", [][]*big.Int{
			{x1, share1, big.NewInt(0)},
			{x2, share2, big.NewInt(0)},
			{x3, share3, big.NewInt(0)},
		}, secrertRandomKey, nil),
		Entry("(x-cooord, share, rank):", [][]*big.Int{
			{setx1, setShare1, big.NewInt(0)},
			{setx2, setShare2, big.NewInt(0)},
			{setx3, setShare3, big.NewInt(0)},
		}, nil, pubKey),
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

	var err error
	for i := 0; i < threshold; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, threshold)
		pm.Set(signersMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		signers[id], err = NewSigner(expPublic, peerManagers[i], uint32(threshold), ss[i][1], bks, msg, listeners[id])
		Expect(err).Should(BeNil())
		signersMain[id] = signers[id]
		r, err := signers[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return signers, listeners
}
