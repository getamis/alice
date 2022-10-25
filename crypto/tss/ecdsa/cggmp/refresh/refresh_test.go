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
package refresh

import (
	"math/big"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestRefresh(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Refresh Suite")
}

var (
	// Assume that threshold <= totalParty
	secret    = big.NewInt(21313513)
	publicKey = pt.ScalarBaseMult(elliptic.Secp256k1(), secret)
)

var _ = Describe("Refresh", func() {
	DescribeTable("NewDKG()", func(threshold uint32, ranks []uint32) {
		totalParty := len(ranks)
		curve := publicKey.GetCurve()
		fieldOrder := curve.Params().N
		shares, bksSlice, err := gernerateShare(curve, threshold, ranks)
		Expect(err).Should(BeNil())

		// new peer managers and dkgs
		refreshes, bks, listeners := newRefreshes(threshold, totalParty, shares, bksSlice)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, d := range refreshes {
			d.Start()
		}
		time.Sleep(2 * time.Second)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		// Set new shares
		afterShares := make([]*big.Int, len(shares))
		afterPartialRefreshPubKeys := make([]*pt.ECPoint, len(shares))

		r0, err := refreshes[tss.GetTestID(0)].GetResult()
		Expect(err).Should(BeNil())
		for i := 0; i < len(afterShares); i++ {
			r, err := refreshes[tss.GetTestID(i)].GetResult()
			Expect(err).Should(BeNil())
			afterShares[i] = r.refreshShare
			afterPartialRefreshPubKeys[i] = r0.refreshPartialPubKey[tss.GetTestID(i)]
		}
		// check that all refresh partial public keys, Y, pedParameters are all the same.
		for i := 1; i < len(shares); i++ {
			r, err := refreshes[tss.GetTestID(i)].GetResult()
			Expect(err).Should(BeNil())
			for k, v := range r0.refreshPartialPubKey {
				Expect(v.Equal(r.refreshPartialPubKey[k])).Should(BeTrue())
			}
			for k, v := range r0.y {
				Expect(v.Equal(r.y[k])).Should(BeTrue())
			}
			for k, v := range r0.pedParameter {
				Expect(v.Getn().Cmp(r.pedParameter[k].Getn()) == 0).Should(BeTrue())
				Expect(v.Gets().Cmp(r.pedParameter[k].Gets()) == 0).Should(BeTrue())
				Expect(v.Gett().Cmp(r.pedParameter[k].Gett()) == 0).Should(BeTrue())
			}
		}

		// check all paillier keys work by comparing the same "N".
		for i := 0; i < len(shares); i++ {
			r, err := refreshes[tss.GetTestID(i)].GetResult()
			Expect(err).Should(BeNil())
			otherIndex := (i + 1) % len(shares)
			rpai, err := refreshes[tss.GetTestID(otherIndex)].GetResult()
			Expect(err).Should(BeNil())
			Expect(r.refreshPaillierKey.GetN().Cmp(rpai.pedParameter[tss.GetTestID(i)].Getn()) == 0).Should(BeTrue())
		}

		allBks := make(birkhoffinterpolation.BkParameters, len(shares))
		for i := 0; i < len(allBks); i++ {
			allBks[i] = bks[tss.GetTestID(i)]
		}
		bkcoefficient, err := allBks.ComputeBkCoefficient(threshold, fieldOrder)
		Expect(err).Should(BeNil())
		gotSecret := new(big.Int).Mul(afterShares[0], bkcoefficient[0])
		gotSecret.Mod(gotSecret, fieldOrder)
		gotPubKey := afterPartialRefreshPubKeys[0].ScalarMult(bkcoefficient[0])
		for i := 1; i < len(afterShares); i++ {
			gotSecret.Add(gotSecret, new(big.Int).Mul(afterShares[i], bkcoefficient[i]))
			gotSecret.Mod(gotSecret, fieldOrder)
			gotPubKey, err = gotPubKey.Add(afterPartialRefreshPubKeys[i].ScalarMult(bkcoefficient[i]))
			Expect(err).Should(BeNil())
		}
		// Check all partial public keys are correct.
		Expect(gotSecret.Cmp(secret) == 0).Should(BeTrue())
		Expect(gotPubKey.Equal(publicKey)).Should(BeTrue())
	},
		Entry("Case #0", uint32(2),
			[]uint32{
				0, 0, 0,
			},
		),
		Entry("Case #1", uint32(2),
			[]uint32{
				0, 1, 1,
			},
		),
		Entry("Case #2", uint32(3),
			[]uint32{
				0, 1, 2,
			},
		),
	)
})

func newRefreshes(threshold uint32, totalParty int, shareSlice []*big.Int, bksPara []*birkhoffinterpolation.BkParameter) (map[string]*Refresh, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	lens := totalParty
	refreshes := make(map[string]*Refresh, lens)
	refreshesMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	bks := make(map[string]*birkhoffinterpolation.BkParameter)
	share := make(map[string]*big.Int)
	partialPubKey := make(map[string]*pt.ECPoint)
	for i := 0; i < totalParty; i++ {
		bks[tss.GetTestID(i)] = bksPara[i]
		share[tss.GetTestID(i)] = shareSlice[i]
		partialPubKey[tss.GetTestID(i)] = pt.ScalarBaseMult(publicKey.GetCurve(), shareSlice[i])
	}

	keySize := 2048
	ssidInfo := []byte("A")
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(refreshesMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		refreshes[id], err = NewRefresh(share[id], publicKey, peerManagers[i], threshold, partialPubKey, bks, keySize, ssidInfo, listeners[id])
		Expect(err).Should(BeNil())
		refreshesMain[id] = refreshes[id]
		r, err := refreshes[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return refreshes, bks, listeners
}

func gernerateShare(curve elliptic.Curve, threshold uint32, ranks []uint32) ([]*big.Int, []*birkhoffinterpolation.BkParameter, error) {
	totalParty := len(ranks)
	poly, err := polynomial.RandomPolynomial(curve.Params().N, threshold-1)
	if err != nil {
		return nil, nil, err
	}
	poly.SetConstant(secret)
	share := make([]*big.Int, totalParty)
	bk := make([]*birkhoffinterpolation.BkParameter, totalParty)
	for i := 0; i < len(share); i++ {
		tempPoly := poly.Differentiate(ranks[i])
		share[i] = tempPoly.Evaluate(big.NewInt(int64(i) + 1))
		bk[i] = birkhoffinterpolation.NewBkParameter(big.NewInt(int64(i)+1), ranks[i])
	}
	return share, bk, nil
}
