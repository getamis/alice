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

package oldpeer

import (
	"math/big"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/elliptic"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestAddShare(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Add Share Suite")
}

var _ = Describe("AddShare", func() {
	curve := elliptic.Secp256k1()
	newPeerID := "new-peer"

	DescribeTable("NewAddShare", func(threshold uint32, bks []*birkhoffinterpolation.BkParameter, newPeerRank uint32) {
		addShares, listeners := newAddShares(curve, threshold, bks, newPeerID)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}

		// Build the new bk.
		x, err := utils.RandomPositiveInt(curve.Params().N)
		Expect(err).Should(BeNil())
		newBk := birkhoffinterpolation.NewBkParameter(x, newPeerRank)

		// Send the new peer bk to the old peer.
		newBkMsg := &addshare.Message{
			Type: addshare.Type_NewBk,
			Id:   newPeerID,
			Body: &addshare.Message_NewBk{
				NewBk: &addshare.BodyNewBk{
					Bk: newBk.ToMessage(),
				},
			},
		}
		for _, addShare := range addShares {
			Expect(addShare.AddMessage(newBkMsg)).Should(BeNil())
		}
		time.Sleep(1 * time.Second)

		newShare := big.NewInt(0)
		for _, addShare := range addShares {
			// Expect that the peer handler and the compute handler handled the message but the verify handler hasn't handled the message yet.
			Expect(addShare.ph.IsHandled(log.Discard(), newPeerID)).Should(BeTrue())
			h := addShare.GetHandler()
			vh, ok := h.(*verifyHandler)
			Expect(ok).Should(BeTrue())
			Expect(vh.IsHandled(log.Discard(), newPeerID)).Should(BeFalse())
			newShare.Add(newShare, vh.deltaI)
		}
		newShare.Mod(newShare, curve.Params().N)

		// Build the new peer's siG proof
		siGProofMsg, err := zkproof.NewBaseSchorrMessage(curve, newShare)
		Expect(err).Should(BeNil())

		// Send the new peer siG proof to the old peer.
		verifyMsg := &addshare.Message{
			Type: addshare.Type_Verify,
			Id:   newPeerID,
			Body: &addshare.Message_Verify{
				Verify: &addshare.BodyVerify{
					SiGProofMsg: siGProofMsg,
				},
			},
		}
		for _, addShare := range addShares {
			Expect(addShare.AddMessage(verifyMsg)).Should(BeNil())
		}
		time.Sleep(1 * time.Second)

		for _, addShare := range addShares {
			// Expect that the verify handler handled the message and the result is not empty.
			addShare.Stop()
			h := addShare.GetHandler()
			vh, ok := h.(*verifyHandler)
			Expect(ok).Should(BeTrue())
			Expect(vh.IsHandled(log.Discard(), newPeerID)).Should(BeTrue())
			r, err := addShare.GetResult()
			Expect(err).Should(BeNil())
			Expect(r.Share).ShouldNot(BeNil())
			Expect(r.Bks[newPeerID]).ShouldNot(BeNil())
		}
	},
		Entry("Case #0", uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
			}, uint32(0),
		),
		Entry("Case #1", uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(5), uint32(1)),
			}, uint32(0),
		),
		Entry("Case #2", uint32(3),
			[]*birkhoffinterpolation.BkParameter{
				birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(1)),
				birkhoffinterpolation.NewBkParameter(big.NewInt(5), uint32(1)),
			}, uint32(1),
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
		addShares := make(map[string]*AddShare, lens)
		addShareMains := make(map[string]types.MessageMain, lens)
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
			// Create one more peer deliberately
			pm := tss.NewTestPeerManager(i, lens+1)
			pm.Set(addShareMains)
			peerManagers[i] = pm
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateFailed).Once()
			tempPoly := poly.Differentiate(ranks[i])
			oldShare := tempPoly.Evaluate(xs[i])
			addShares[id], err = NewAddShare(peerManagers[i], pubkey, threshold, oldShare, bks, newPeerID, listener[i])
			Expect(err).Should(Equal(tss.ErrInconsistentPeerNumAndBks))
			addShareMains[id] = addShares[id]
		}
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
			pm := tss.NewTestPeerManager(i, lens)
			peerManagers[i] = pm
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateFailed).Once()
			tempPoly := poly.Differentiate(ranks[i])
			oldShare := tempPoly.Evaluate(xs[i])
			_, err = NewAddShare(peerManagers[i], pubkey, threshold, oldShare, bks, newPeerID, listener[i])
			Expect(err).Should(Equal(utils.ErrLargeThreshold))
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
		_, err = NewAddShare(pm, pubkey, threshold, oldShare, bks, newPeerID, listener)
		Expect(err).Should(Equal(tss.ErrSelfBKNotFound))
	})
})

func newAddShares(c elliptic.Curve, threshold uint32, bks []*birkhoffinterpolation.BkParameter, newPeerID string) (map[string]*AddShare, map[string]*mocks.StateChangedListener) {
	// new peer managers and reshares
	lens := len(bks)
	addShares := make(map[string]*AddShare, lens)
	addShareMains := make(map[string]types.MessageMain, lens)
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
		pm.Set(addShareMains)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		tempPoly := poly.Differentiate(bks[i].GetRank())
		oldShare := tempPoly.Evaluate(bks[i].GetX())
		addShares[id], err = NewAddShare(peerManagers[i], pubkey, threshold, oldShare, bksMap, newPeerID, listeners[id])
		Expect(err).Should(BeNil())
		addShareMains[id] = addShares[id]
		r, err := addShares[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
		addShares[id].Start()
	}
	return addShares, listeners
}
