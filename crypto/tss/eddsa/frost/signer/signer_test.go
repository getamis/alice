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
		curve = elliptic.Ed25519()
	)

	DescribeTable("It should be OK", func(ss [][]*big.Int, privateKey *big.Int) {
		expPublic := ecpointgrouplaw.ScalarBaseMult(curve, privateKey)
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

		Expect(edwards.Verify(edwardPubKey, message, r, s)).Should(BeTrue())
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("(x-cooord, share, rank):f(x) = 2x+100", [][]*big.Int{
			{big.NewInt(1), big.NewInt(102), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(104), big.NewInt(0)},
			{big.NewInt(8), big.NewInt(116), big.NewInt(0)},
		}, big.NewInt(100)),
		Entry("(x-cooord, share, rank):f(x) = 2x+100", [][]*big.Int{
			{big.NewInt(1), big.NewInt(102), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(104), big.NewInt(0)},
		}, big.NewInt(100)),
		Entry("(x-cooord, share, rank):f(x) = x^2+5*x+1109", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1115), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(1123), big.NewInt(0)},
			{big.NewInt(50), big.NewInt(3859), big.NewInt(0)},
		}, big.NewInt(1109)),
		Entry("(x-cooord, share, rank):f(x) = x^2+3*x+5555", [][]*big.Int{
			{big.NewInt(1), big.NewInt(5559), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(5565), big.NewInt(0)},
			{big.NewInt(50), big.NewInt(103), big.NewInt(1)},
		}, big.NewInt(5555)),
		Entry("(x-cooord, share, rank):f(x) = 2*x^2+3*x+1111", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1116), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(4), big.NewInt(2)},
			{big.NewInt(50), big.NewInt(203), big.NewInt(1)},
		}, big.NewInt(1111)),
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
