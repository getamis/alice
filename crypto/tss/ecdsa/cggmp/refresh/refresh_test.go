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
	. "github.com/onsi/gomega"
)

func TestRefresh(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Refresh Suite")
}

var (
	// Assume that threshold <= totalParty
	threshold  = uint32(2)
	totalParty = 3
	secret     = big.NewInt(21313513)
	publicKey  = pt.ScalarBaseMult(elliptic.Secp256k1(), secret)
)

var _ = Describe("Refresh", func() {
	It("should be ok", func() {
		curve := publicKey.GetCurve()
		fieldOrder := curve.Params().N
		shares, partialPubKeys, err := gernerateShare(curve)
		Expect(err).Should(BeNil())

		// new peer managers and dkgs
		refreshes, bks, listeners := newRefreshes()
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, d := range refreshes {
			d.Start()
		}
		time.Sleep(3 * time.Second)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		// Set new shares and all partial public keys.
		afterShares := make([]*big.Int, len(shares))
		afterPartialRefreshPubKeys := make([]*pt.ECPoint, len(partialPubKeys))
		for i := 0; i < len(afterShares); i++ {
			r, err := refreshes[tss.GetTestID(i)].GetResult()
			Expect(err).Should(BeNil())
			afterShares[i] = new(big.Int).Add(r.refreshShare, shares[i])
			afterPartialRefreshPubKeys[i], err = r.sumpartialPubKey[tss.GetTestID(i)].Add(partialPubKeys[i])
			Expect(err).Should(BeNil())
		}

		// check that all refresh partial public keys are the same.
		r0, err := refreshes[tss.GetTestID(0)].GetResult()
		Expect(err).Should(BeNil())
		for i := 1; i < len(shares); i++ {
			r, err := refreshes[tss.GetTestID(i)].GetResult()
			Expect(err).Should(BeNil())
			for k, v := range r0.sumpartialPubKey {
				Expect(v.Equal(r.sumpartialPubKey[k])).Should(BeTrue())
			}
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
	})
})

func newRefreshes() (map[string]*Refresh, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	lens := totalParty
	refreshes := make(map[string]*Refresh, lens)
	refreshesMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	bks := make(map[string]*birkhoffinterpolation.BkParameter)
	for i := 0; i < totalParty; i++ {
		bks[tss.GetTestID(i)] = birkhoffinterpolation.NewBkParameter(big.NewInt(int64(i)+1), 0)
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
		refreshes[id], err = NewRefresh(publicKey, peerManagers[i], threshold, bks, keySize, ssidInfo, listeners[id])
		Expect(err).Should(BeNil())
		refreshesMain[id] = refreshes[id]
		r, err := refreshes[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return refreshes, bks, listeners
}

// Assume that the bk coefficient are (1,0), (2, 0),...,(n+1, 0)
func gernerateShare(curve elliptic.Curve) ([]*big.Int, []*pt.ECPoint, error) {
	poly, err := polynomial.RandomPolynomial(curve.Params().N, threshold-1)
	if err != nil {
		return nil, nil, err
	}
	poly.SetConstant(secret)

	share := make([]*big.Int, totalParty)
	partialPubKey := make([]*pt.ECPoint, totalParty)
	for i := 0; i < len(share); i++ {
		share[i] = poly.Evaluate(big.NewInt(int64(i) + 1))
		partialPubKey[i] = pt.ScalarBaseMult(curve, share[i])
	}
	return share, partialPubKey, nil
}
