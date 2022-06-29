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
	threshold = uint32(2)
	secret    = big.NewInt(2)
	publicKey = pt.ScalarBaseMult(elliptic.Secp256k1(), secret)
)

var _ = Describe("Refresh", func() {
	It("should be ok", func() {
		// new peer managers and dkgs
		refreshes, bks, listeners := newRefreshes()
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, d := range refreshes {
			d.Start()
		}
		time.Sleep(1 * time.Second)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		r, err := refreshes[tss.GetTestID(0)].GetResult()
		Expect(err).Should(BeNil())
		shareA := big.NewInt(3)
		afterShareA := new(big.Int).Add(r.refreshShare, shareA)

		r, err = refreshes[tss.GetTestID(1)].GetResult()
		Expect(err).Should(BeNil())
		shareB := big.NewInt(4)
		afterShareB := new(big.Int).Add(r.refreshShare, shareB)

		allBks := birkhoffinterpolation.BkParameters{bks[tss.GetTestID(0)], bks[tss.GetTestID(1)]}
		bkcoefficient, err := allBks.ComputeBkCoefficient(threshold, publicKey.GetCurve().Params().N)
		Expect(err).Should(BeNil())
		gotSecret := new(big.Int).Add(new(big.Int).Mul(afterShareA, bkcoefficient[0]), new(big.Int).Mul(afterShareB, bkcoefficient[1]))
		gotSecret.Mod(gotSecret, publicKey.GetCurve().Params().N)
		Expect(gotSecret.Cmp(secret) == 0).Should(BeTrue())
	})
})

func newRefreshes() (map[string]*Refresh, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	lens := 2
	refreshes := make(map[string]*Refresh, lens)
	refreshesMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	bks := map[string]*birkhoffinterpolation.BkParameter{
		tss.GetTestID(0): birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0),
		tss.GetTestID(1): birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0),
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
