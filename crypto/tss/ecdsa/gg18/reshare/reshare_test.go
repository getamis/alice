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
package reshare

import (
	"math/big"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/elliptic"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestReshare(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Reshare Suite")
}

var _ = Describe("Reshare", func() {
	curve := elliptic.Secp256k1()
	DescribeTable("NewReshare()", func(c elliptic.Curve, threshold uint32, bks []*birkhoffinterpolation.BkParameter) {
		reshares, listeners := newReshares(c, threshold, bks)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}

		for _, r := range reshares {
			r.Start()
		}
		time.Sleep(1 * time.Second)

		for _, d := range reshares {
			d.Stop()
			_, err := d.GetResult()
			Expect(err).Should(BeNil())
		}

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("Case #0", curve, uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(5), uint32(0)),
			},
		),
		Entry("Case #1", curve, uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0)),
			},
		),
		Entry("Case #2", curve, uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
			},
		),
		Entry("Case #3", curve, uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(5), uint32(1)),
			},
		),
		Entry("Case #4", curve, uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(5), uint32(1)),
			},
		),
		Entry("Case #5", curve, uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(5), uint32(1)),
			},
		),
	)

	It("not enough birkhoff", func() {
		xs := []*big.Int{
			big.NewInt(1), big.NewInt(5000), big.NewInt(1221),
		}
		threshold := uint32(3)
		ranks := []uint32{
			0, 0, 0,
		}
		// new peer managers and reshares
		lens := len(ranks)
		peerManagers := make([]types.PeerManager, lens)
		bks := make(map[string]*birkhoffinterpolation.BkParameter)
		listener := make([]*mocks.StateChangedListener, lens)

		// Build old shares, and public key
		poly, err := polynomial.RandomPolynomial(curve.Params().N, threshold-1)
		Expect(err).Should(BeNil())
		pubkey := ecpointgrouplaw.ScalarBaseMult(curve, poly.Get(0))

		// Build bks
		for i := 0; i < lens; i++ {
			id := tss.GetTestID(i)
			bks[id] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
		}

		for i := 0; i < lens; i++ {
			// Create one more peer deliberately
			pm := tss.NewTestPeerManager(i, lens+1)
			peerManagers[i] = pm
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateFailed).Once()
			tempPoly := poly.Differentiate(ranks[i])
			oldShare := tempPoly.Evaluate(xs[i])
			_, err = NewReshare(peerManagers[i], threshold, pubkey, oldShare, bks, listener[i])
			Expect(err).Should(Equal(tss.ErrNotEnoughBKs))
		}
	})

	It("self birkhoff not found", func() {
		xs := []*big.Int{
			big.NewInt(1), big.NewInt(5000), big.NewInt(1221),
		}
		threshold := uint32(2)
		ranks := []uint32{
			0, 0, 0,
		}
		lens := len(ranks)
		bks := make(map[string]*birkhoffinterpolation.BkParameter)
		listener := new(mocks.StateChangedListener)
		pubkey := ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(100))
		oldShare := big.NewInt(50)

		// Build bks
		for i := 0; i < lens; i++ {
			// Deliberately plus 1 to make bks[0] not found
			id := tss.GetTestID(i + 1)
			bks[id] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
		}

		pm := tss.NewTestPeerManager(0, lens)
		listener.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
		var err error
		_, err = NewReshare(pm, threshold, pubkey, oldShare, bks, listener)
		Expect(err).Should(Equal(tss.ErrSelfBKNotFound))
	})

	It("large threshold", func() {
		xs := []*big.Int{
			big.NewInt(1), big.NewInt(5000), big.NewInt(1221),
		}
		threshold := uint32(4)
		ranks := []uint32{
			0, 0, 0,
		}
		// new peer managers and reshares
		lens := len(ranks)
		reshares := make(map[string]*Reshare, lens)
		peerManagers := make([]types.PeerManager, lens)
		bks := make(map[string]*birkhoffinterpolation.BkParameter)
		listener := make([]*mocks.StateChangedListener, lens)

		// Build old shares, and public key
		poly, err := polynomial.RandomPolynomial(curve.Params().N, threshold-1)
		Expect(err).Should(BeNil())
		pubkey := ecpointgrouplaw.ScalarBaseMult(curve, poly.Get(0))

		// Build bks
		for i := 0; i < lens; i++ {
			id := tss.GetTestID(i)
			bks[id] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
		}

		for i := 0; i < lens; i++ {
			id := tss.GetTestID(i)
			pm := tss.NewTestPeerManager(i, lens)
			peerManagers[i] = pm
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateFailed).Once()
			tempPoly := poly.Differentiate(ranks[i])
			oldShare := tempPoly.Evaluate(xs[i])
			var err error
			reshares[id], err = NewReshare(peerManagers[i], threshold, pubkey, oldShare, bks, listener[i])
			Expect(err).Should(Equal(utils.ErrLargeThreshold))
		}
	})
})

type peerManager struct {
	id       string
	numPeers uint32
	reshares map[string]*Reshare
}

func newReshares(c elliptic.Curve, threshold uint32, bks []*birkhoffinterpolation.BkParameter) (map[string]*Reshare, map[string]*mocks.StateChangedListener) {
	// new peer managers and reshares
	lens := len(bks)
	reshares := make(map[string]*Reshare, lens)
	reshareMains := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	bksMap := make(map[string]*birkhoffinterpolation.BkParameter)
	listeners := make(map[string]*mocks.StateChangedListener, lens)

	// Build old shares, and public key
	poly, err := polynomial.RandomPolynomial(c.Params().N, threshold-1)
	Expect(err).Should(BeNil())
	pubkey := ecpointgrouplaw.ScalarBaseMult(c, poly.Get(0))

	// Convert bks to map
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		bksMap[id] = bks[i]
	}

	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(reshareMains)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		tempPoly := poly.Differentiate(bks[i].GetRank())
		oldShare := tempPoly.Evaluate(bks[i].GetX())
		reshares[id], err = NewReshare(peerManagers[i], threshold, pubkey, oldShare, bksMap, listeners[id])
		Expect(err).Should(BeNil())
		reshareMains[id] = reshares[id]
		r, err := reshares[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return reshares, listeners
}
