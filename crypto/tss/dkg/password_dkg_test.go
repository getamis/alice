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
package dkg

import (
	"math/big"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	oprf "github.com/getamis/alice/crypto/oprf"
	"github.com/getamis/alice/crypto/oprf/hasher"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/tss/message/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var (
	secp256k1Hasher = hasher.NewSECP256k1()
)

var _ = Describe("Password DKG", func() {
	DescribeTable("Password DKG", func(password []byte) {

		// new peer managers and dkgs
		dkgs, listeners := newPasswordDKGs(password)
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
			ph := d.ph.GetPeerHandler()
			secret = new(big.Int).Add(secret, ph.poly.Get(0))
		}
		pubkey := ecpointgrouplaw.ScalarBaseMult(btcec.S256(), secret)
		serverKValue := big.NewInt(0)
		for _, d := range dkgs {
			r, err := d.GetResult()
			Expect(err).Should(BeNil())
			if r.K != nil {
				serverKValue.Add(serverKValue, r.K)
				serverKValue.Mod(serverKValue, pubkey.GetCurve().Params().N)
			}
			Expect(r.PublicKey.Equal(pubkey)).Should(BeTrue())
		}

		expectedUserShare, err := oprf.ComputeShare(serverKValue, password, secp256k1Hasher)
		Expect(err).Should(BeNil())
		for _, d := range dkgs {
			r, err := d.GetResult()
			Expect(err).Should(BeNil())
			if r.K == nil {
				Expect(r.Share.Cmp(expectedUserShare) == 0).Should(BeTrue())
			}
		}

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("Case #0", []byte("edwin-haha")),
		Entry("Case #1", []byte("cy-haha")),
		Entry("Case #2", []byte("bun-haha")),
	)
})

func newPasswordDKGs(password []byte) (map[string]*DKG, map[string]*mocks.StateChangedListener) {
	lens := 2
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
		if i == 0 {
			dkgs[id], err = NewPasswordUserDKG(peerManagers[i], listeners[id], password)
		} else {
			dkgs[id], err = NewPasswordServerDKG(peerManagers[i], listeners[id])
		}
		Expect(err).Should(BeNil())
		dkgsMain[id] = dkgs[id]
		r, err := dkgs[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return dkgs, listeners
}
