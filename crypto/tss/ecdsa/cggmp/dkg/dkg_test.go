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
package dkg

import (
	"math/big"
	"testing"
	"time"

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
)

func TestDKG(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "DKG Suite")
}

var _ = Describe("DKG", func() {
	sid := make([]byte, 1)
	curve := elliptic.Secp256k1()
	DescribeTable("NewDKG()", func(c elliptic.Curve, threshold uint32, ranks []uint32) {
		// new peer managers and dkgs
		dkgs, listeners := newDKGs(c, sid, threshold, ranks)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, d := range dkgs {
			d.Start()
		}
		time.Sleep(1 * time.Second)

		// Build public key
		secret := big.NewInt(0)
		for _, d := range dkgs {
			d.Stop()
			secret = new(big.Int).Add(secret, d.ph.poly.Get(0))
		}
		pubkey := ecpointgrouplaw.ScalarBaseMult(c, secret)
		for _, d := range dkgs {
			r, err := d.GetResult()
			Expect(err).Should(BeNil())
			Expect(r.PublicKey.Equal(pubkey)).Should(BeTrue())
		}

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("Case #0", curve, uint32(3),
			[]uint32{
				0, 0, 0, 0, 0,
			},
		),
		Entry("Case #1", curve, uint32(3),
			[]uint32{
				0, 0, 0, 1, 1,
			},
		),
		Entry("Case #2", curve, uint32(3),
			[]uint32{
				0, 0, 1, 1, 1,
			},
		),
	)

	DescribeTable("newDKGWithHandler", func(c elliptic.Curve, threshold uint32, coefficients [][]*big.Int, x []*big.Int, ranks []uint32, expectShare []*big.Int, expPubKey *ecpointgrouplaw.ECPoint) {
		sid := make([]byte, 1)
		dkgs, listeners := newDKGWithPeerHandler(c, sid, threshold, ranks, x, coefficients)
		// new peer managers and dkgs
		lens := len(ranks)
		bks := make(map[string]*birkhoffinterpolation.BkParameter, lens)
		for i := 0; i < lens; i++ {
			id := tss.GetTestID(i)
			bks[id] = birkhoffinterpolation.NewBkParameter(x[i], ranks[i])
		}
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, d := range dkgs {
			d.Start()
		}
		time.Sleep(1 * time.Second)

		secret := big.NewInt(0)
		for i := 0; i < len(dkgs); i++ {
			id := tss.GetTestID(i)
			d := dkgs[id]
			d.Stop()
			r, err := d.GetResult()
			Expect(err).Should(BeNil())
			Expect(r.Share).Should(Equal(new(big.Int).Mod(expectShare[i], curve.Params().N)))
			Expect(r.PublicKey.Equal(expPubKey)).Should(BeTrue())
			Expect(r.Bks).Should(Equal(bks))
			secret = new(big.Int).Add(secret, d.ph.poly.Get(0))
		}
		pubkey := ecpointgrouplaw.ScalarBaseMult(c, secret)
		Expect(pubkey.Equal(expPubKey)).Should(BeTrue())
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("Case #0", curve, uint32(3), [][]*big.Int{
			{
				big.NewInt(1), big.NewInt(1), big.NewInt(1),
			},
			{
				big.NewInt(5), big.NewInt(2), big.NewInt(3),
			},
			{
				big.NewInt(13), big.NewInt(0), big.NewInt(100),
			},
			{
				big.NewInt(0), big.NewInt(87), big.NewInt(56),
			},
			{
				big.NewInt(23), big.NewInt(1), big.NewInt(123),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(5), big.NewInt(11), big.NewInt(16), big.NewInt(7),
		},
			[]uint32{
				0, 0, 0, 0, 0,
			},
			[]*big.Int{
				big.NewInt(416), big.NewInt(7572), big.NewInt(35286), big.NewInt(73946), big.NewInt(14546),
			},
			ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(42)),
		),
		Entry("Case #1", curve, uint32(3), [][]*big.Int{
			{
				big.NewInt(1), big.NewInt(1), big.NewInt(1),
			},
			{
				big.NewInt(5), big.NewInt(2), big.NewInt(3),
			},
			{
				big.NewInt(13), big.NewInt(0), big.NewInt(100),
			},
			{
				big.NewInt(0), big.NewInt(87), big.NewInt(56),
			},
			{
				big.NewInt(23), big.NewInt(1), big.NewInt(123),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(5), big.NewInt(11), big.NewInt(16), big.NewInt(7),
		},
			[]uint32{
				0, 0, 1, 1, 0,
			},
			[]*big.Int{
				big.NewInt(416), big.NewInt(7572), big.NewInt(6317), big.NewInt(9147), big.NewInt(14546),
			},
			ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(42)),
		),
		Entry("Case #2", curve, uint32(3), [][]*big.Int{
			{
				big.NewInt(1011), big.NewInt(1), big.NewInt(0),
			},
			{
				big.NewInt(512), big.NewInt(2), big.NewInt(0),
			},
			{
				big.NewInt(131232), big.NewInt(0), big.NewInt(0),
			},
			{
				big.NewInt(0), big.NewInt(87), big.NewInt(0),
			},
			{
				big.NewInt(231232), big.NewInt(1), big.NewInt(0),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(5000), big.NewInt(1221), big.NewInt(16234), big.NewInt(1231237),
		},
			[]uint32{
				0, 0, 1, 0, 0,
			},
			[]*big.Int{
				big.NewInt(364078), big.NewInt(818987), big.NewInt(91), big.NewInt(1841281), big.NewInt(112406554),
			},
			ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(363987)),
		),
		Entry("Case #3", curve, uint32(4), [][]*big.Int{
			{
				big.NewInt(11), big.NewInt(1), big.NewInt(90), big.NewInt(24),
			},
			{
				big.NewInt(294), big.NewInt(2), big.NewInt(80), big.NewInt(0),
			},
			{
				big.NewInt(1312), big.NewInt(12), big.NewInt(0), big.NewInt(0),
			},
			{
				big.NewInt(331), big.NewInt(87), big.NewInt(11), big.NewInt(0),
			},
			{
				big.NewInt(2332), big.NewInt(1), big.NewInt(0), big.NewInt(13),
			},
		}, []*big.Int{
			big.NewInt(818), big.NewInt(52320), big.NewInt(12887), big.NewInt(12434), big.NewInt(132114),
		},
			[]uint32{
				0, 0, 1, 0, 2,
			},
			[]*big.Int{
				big.NewInt(20372906962), big.NewInt(5299629816823640), big.NewInt(18438964556), big.NewInt(71154955486066), big.NewInt(29329670),
			},
			ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(4280)),
		),
		Entry("Case #4", curve, uint32(3), [][]*big.Int{
			{
				big.NewInt(1011), big.NewInt(1), big.NewInt(1),
			},
			{
				big.NewInt(512), big.NewInt(2), big.NewInt(2),
			},
			{
				big.NewInt(131232), big.NewInt(11), big.NewInt(30),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(5000), big.NewInt(1221),
		},
			[]uint32{
				0, 0, 0,
			},
			[]*big.Int{
				big.NewInt(132802), big.NewInt(825202755), big.NewInt(49347602),
			},
			ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(132755)),
		),
		Entry("Case #5", curve, uint32(3), [][]*big.Int{
			{
				big.NewInt(-1011), big.NewInt(1), big.NewInt(1),
			},
			{
				big.NewInt(512), big.NewInt(2), big.NewInt(2),
			},
			{
				big.NewInt(131232), big.NewInt(11), big.NewInt(30),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(5000), big.NewInt(1221),
		},
			[]uint32{
				0, 0, 0,
			},
			[]*big.Int{
				big.NewInt(130780), big.NewInt(825200733), big.NewInt(49345580),
			},
			ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(130733)),
		),
		Entry("Case #5", curve, uint32(4), [][]*big.Int{
			{
				big.NewInt(-1011), big.NewInt(-1), big.NewInt(-1), big.NewInt(-1),
			},
			{
				big.NewInt(-512), big.NewInt(-2), big.NewInt(-2), big.NewInt(-200),
			},
			{
				big.NewInt(-1312), big.NewInt(-11), big.NewInt(-30), big.NewInt(-5),
			},
			{
				big.NewInt(-919), big.NewInt(-11), big.NewInt(-30), big.NewInt(-818),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(50), big.NewInt(11), big.NewInt(91),
		},
			[]uint32{
				0, 0, 0, 1,
			},
			[]*big.Int{
				big.NewInt(-4866), big.NewInt(-128162504), big.NewInt(-1374596), big.NewInt(-25450723),
			},
			ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(-3754)),
		),
		Entry("Case #6", curve, uint32(4), [][]*big.Int{
			{
				big.NewInt(-1011), big.NewInt(-1), big.NewInt(-1), big.NewInt(-1),
			},
			{
				big.NewInt(-512), big.NewInt(-2), big.NewInt(-2), big.NewInt(-200),
			},
			{
				big.NewInt(-1312), big.NewInt(-11), big.NewInt(-30), big.NewInt(-5),
			},
			{
				big.NewInt(-919), big.NewInt(-11), big.NewInt(-30), big.NewInt(-818),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(50), big.NewInt(11), big.NewInt(91),
		},
			[]uint32{
				0, 1, 2, 2,
			},
			[]*big.Int{
				big.NewInt(-4866), big.NewInt(-7686325), big.NewInt(-67710), big.NewInt(-559230),
			},
			ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(-3754)),
		),
	)

	DescribeTable("negative cases", func(c elliptic.Curve, threshold uint32, coefficients [][]*big.Int, x []*big.Int, ranks []uint32) {
		sid := make([]byte, 1)
		// new peer managers and dkgs
		dkgs, listeners := newDKGWithPeerHandler(c, sid, threshold, ranks, x, coefficients)
		for _, d := range dkgs {
			d.Start()
		}
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
		}
		time.Sleep(time.Second)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("trivial public key", curve, uint32(3), [][]*big.Int{
			{
				big.NewInt(0), big.NewInt(1), big.NewInt(1),
			},
			{
				big.NewInt(0), big.NewInt(2), big.NewInt(2),
			},
			{
				big.NewInt(0), big.NewInt(11), big.NewInt(30),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(5000), big.NewInt(1221),
		},
			[]uint32{
				0, 0, 0,
			},
		),
		Entry("can not recover secret key, because can not get birkhoff coefficients", curve, uint32(3), [][]*big.Int{
			{
				big.NewInt(-1), big.NewInt(1), big.NewInt(1),
			},
			{
				big.NewInt(0), big.NewInt(2), big.NewInt(2),
			},
			{
				big.NewInt(0), big.NewInt(11), big.NewInt(30),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(3), big.NewInt(2),
		},
			[]uint32{
				0, 0, 1,
			},
		),
		Entry("can not recover secret key, because the lower rank", curve, uint32(3), [][]*big.Int{
			{
				big.NewInt(-1), big.NewInt(1), big.NewInt(1),
			},
			{
				big.NewInt(0), big.NewInt(2), big.NewInt(2),
			},
			{
				big.NewInt(0), big.NewInt(11), big.NewInt(30),
			},
		}, []*big.Int{
			big.NewInt(1), big.NewInt(3), big.NewInt(9),
		},
			[]uint32{
				1, 1, 1,
			},
		),
	)

	It("large threshold", func() {
		coefficients := [][]*big.Int{
			{
				big.NewInt(-1), big.NewInt(1), big.NewInt(1), big.NewInt(1),
			},
			{
				big.NewInt(0), big.NewInt(2), big.NewInt(2), big.NewInt(3),
			},
			{
				big.NewInt(0), big.NewInt(11), big.NewInt(30), big.NewInt(2),
			}}
		x := []*big.Int{
			big.NewInt(1), big.NewInt(5000), big.NewInt(1221),
		}
		threshold := uint32(4)
		ranks := []uint32{
			0, 0, 0,
		}
		lens := len(ranks)
		peerManagers := make([]types.PeerManager, lens)
		sid := make([]byte, 1)
		for i := 0; i < lens; i++ {
			pm := tss.NewTestPeerManager(i, lens)
			peerManagers[i] = pm
			poly, err := polynomial.NewPolynomial(curve.Params().N, coefficients[i])
			Expect(err).Should(BeNil())
			ph, err := newPeerHandlerWithPolynomial(curve, peerManagers[i], sid, threshold, x[i], ranks[i], poly)
			Expect(err).Should(Equal(utils.ErrLargeThreshold))
			Expect(ph).Should(BeNil())
		}
	})

	Context("negative cases", func() {
		sid := make([]byte, 1)
		It("larger threshold", func() {
			d, err := NewDKG(curve, tss.NewTestPeerManager(0, 4), sid, 6, 0, nil)
			Expect(err).Should(Equal(utils.ErrLargeThreshold))
			Expect(d).Should(BeNil())

			d, err = newDKGWithHandler(tss.NewTestPeerManager(0, 4), 6, 0, nil, nil)
			Expect(err).Should(Equal(utils.ErrLargeThreshold))
			Expect(d).Should(BeNil())
		})

		It("large rank", func() {
			d, err := NewDKG(curve, tss.NewTestPeerManager(0, 4), sid, 3, 3, nil)
			Expect(err).Should(Equal(utils.ErrLargeRank))
			Expect(d).Should(BeNil())

			d, err = newDKGWithHandler(tss.NewTestPeerManager(0, 4), 3, 3, nil, nil)
			Expect(err).Should(Equal(utils.ErrLargeRank))
			Expect(d).Should(BeNil())
		})

		It("larger threshold", func() {
			d, err := NewDKG(curve, tss.NewTestPeerManager(0, 5), sid, 5, 0, nil)
			Expect(err).Should(BeNil())
			Expect(d).ShouldNot(BeNil())
			r, err := d.GetResult()
			Expect(err).Should(Equal(tss.ErrNotReady))
			Expect(r).Should(BeNil())

			d, err = newDKGWithHandler(tss.NewTestPeerManager(0, 5), 5, 0, nil, nil)
			Expect(err).Should(BeNil())
			Expect(d).ShouldNot(BeNil())
			r, err = d.GetResult()
			Expect(err).Should(Equal(tss.ErrNotReady))
			Expect(r).Should(BeNil())
		})
	})
})

func newDKGs(curve elliptic.Curve, sid []byte, threshold uint32, ranks []uint32) (map[string]*DKG, map[string]*mocks.StateChangedListener) {
	lens := len(ranks)
	dkgs := make(map[string]*DKG, lens)
	dkgsMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(dkgsMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		dkgs[id], err = NewDKG(curve, peerManagers[i], sid, threshold, ranks[i], listeners[id])
		Expect(err).Should(BeNil())
		dkgsMain[id] = dkgs[id]
		r, err := dkgs[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return dkgs, listeners
}

func newDKGWithPeerHandler(curve elliptic.Curve, sid []byte, threshold uint32, ranks []uint32, x []*big.Int, coefficients [][]*big.Int) (map[string]*DKG, map[string]*mocks.StateChangedListener) {
	lens := len(ranks)
	dkgs := make(map[string]*DKG, lens)
	dkgsMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(dkgsMain)
		peerManagers[i] = pm
		poly, err := polynomial.NewPolynomial(curve.Params().N, coefficients[i])
		Expect(err).Should(BeNil())
		ph, err := newPeerHandlerWithPolynomial(curve, peerManagers[i], sid, threshold, x[i], ranks[i], poly)
		Expect(err).Should(BeNil())
		listeners[id] = new(mocks.StateChangedListener)
		dkgs[id], err = newDKGWithHandler(peerManagers[i], threshold, ranks[i], listeners[id], ph)
		Expect(err).Should(BeNil())
		dkgsMain[id] = dkgs[id]
	}
	return dkgs, listeners
}
