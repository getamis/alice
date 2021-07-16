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
	"crypto/elliptic"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/alice/internal/message/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("SiSigner", func() {
	var (
		curve = btcec.S256()
		msg   = []byte{1, 2, 3}
	)

	DescribeTable("NewSiSigner()", func(ss [][]*big.Int, gScale *big.Int) {
		// new peer managers and dkgs
		expPublic := pt.ScalarBaseMult(curve, gScale)
		threshold := len(ss)
		signers, listeners := newSiSigners(curve, expPublic, ss, msg)
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
		var r *pt.ECPoint
		s := big.NewInt(0)
		for _, signer := range signers {
			signer.Stop()
			result, err := signer.GetResult()
			Expect(err).Should(BeNil())
			// All R and S should be the same
			if r != nil {
				Expect(r).Should(Equal(result.R))
			} else {
				r = result.R
			}
			s = new(big.Int).Add(s, result.Si)
		}
		s = s.Mod(s, curve.N)
		Expect(ecdsa.Verify(expPublic.ToPubKey(), msg, r.GetX(), s)).Should(BeTrue())

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("(shareX, shareY, rank):(1,3,0),(10,111,0),(20,421,0)", [][]*big.Int{
			{big.NewInt(1), big.NewInt(3), big.NewInt(0)},
			{big.NewInt(10), big.NewInt(111), big.NewInt(0)},
			{big.NewInt(20), big.NewInt(421), big.NewInt(0)},
		}, big.NewInt(1)),
	)
})

func newSiSigners(curve elliptic.Curve, expPublic *pt.ECPoint, ss [][]*big.Int, msg []byte, funcs ...func(types.PeerManager) types.PeerManager) (map[string]*SiSigner, map[string]*mocks.StateChangedListener) {
	threshold := len(ss)
	signers := make(map[string]*SiSigner, threshold)
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
		var ppm types.PeerManager = pm
		for _, f := range funcs {
			ppm = f(ppm)
		}
		peerManagers[i] = ppm
		listeners[id] = new(mocks.StateChangedListener)
		homo, err := paillier.NewPaillier(2048)
		Expect(err).Should(BeNil())
		signers[id], err = NewSiSigner(peerManagers[i], expPublic, homo, ss[i][1], bks, msg, listeners[id])
		Expect(err).Should(BeNil())
		signersMain[id] = signers[id]
		r, err := signers[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return signers, listeners
}
