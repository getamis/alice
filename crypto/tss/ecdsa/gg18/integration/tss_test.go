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
package integration

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare/newpeer"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare/oldpeer"
	gDkg "github.com/getamis/alice/crypto/tss/ecdsa/gg18/dkg"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/reshare"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/signer"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"gonum.org/v1/gonum/stat/combin"
)

func TestTSS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TSS Suite")
}

var _ = Describe("TSS", func() {
	DescribeTable("TSS flow", func(c elliptic.Curve, threshold uint32, ranks []uint32) {
		lens := len(ranks)
		listener := make([]*mocks.StateChangedListener, lens)

		// homo functions for signer
		homoFuncs := []func() (homo.Crypto, error){
			func() (homo.Crypto, error) {
				return paillier.NewPaillier(2048)
			},
			func() (homo.Crypto, error) {
				safeParameter := 1348
				distributionDistance := uint(40)
				return cl.NewCL(big.NewInt(1024), 40, c.Params().N, safeParameter, distributionDistance)
			},
		}

		By("Step 1: DKG")
		dkgs := make(map[string]*dkg.DKG, lens)
		msgMain := make(map[string]types.MessageMain, lens)
		dkgPeerManagers := make([]types.PeerManager, lens)
		for i := 0; i < lens; i++ {
			id := tss.GetTestID(i)
			pm := tss.NewTestPeerManager(i, lens)
			pm.Set(msgMain)
			dkgPeerManagers[i] = pm
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateDone).Once()
			var err error
			dkgs[id], err = gDkg.NewDKG(dkgPeerManagers[i], threshold, ranks[i], listener[i])
			Expect(err).Should(BeNil())
			msgMain[id] = dkgs[id]
			dkgResult, err := dkgs[id].GetResult()
			Expect(dkgResult).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrNotReady))
		}

		for _, d := range dkgs {
			d.Start()
		}
		time.Sleep(1 * time.Second)

		// Stop DKG process and record the result.
		var r *result
		for id, dkg := range dkgs {
			dkg.Stop()
			dkgResult, err := dkg.GetResult()
			Expect(err).Should(BeNil())
			if r == nil {
				r = &result{
					publicKey: dkgResult.PublicKey,
					bks:       dkgResult.Bks,
					share:     make(map[string]*big.Int),
				}
			} else {
				// public key and bks should be the same
				Expect(r.publicKey).Should(Equal(dkgResult.PublicKey))
				Expect(r.bks).Should(Equal(dkgResult.Bks))
			}
			r.share[id] = dkgResult.Share
		}
		assertListener(listener, lens)

		By("Step 2: Signer")
		for _, homoFunc := range homoFuncs {
			sign(homoFunc, int(threshold), lens, r, listener)
		}

		By("Step 3: Reshare")
		reshares := make(map[string]*reshare.Reshare, lens)
		msgMain = make(map[string]types.MessageMain, lens)
		resharePeerManagers := make([]types.PeerManager, lens)
		for i := 0; i < lens; i++ {
			id := tss.GetTestID(i)
			pm := tss.NewTestPeerManager(i, lens)
			pm.Set(msgMain)
			resharePeerManagers[i] = pm
			listener[i].On("OnStateChanged", types.StateInit, types.StateDone).Once()
			var err error
			reshares[id], err = reshare.NewReshare(resharePeerManagers[i], threshold, r.publicKey, r.share[id], r.bks, listener[i])
			Expect(err).Should(BeNil())
			msgMain[id] = reshares[id]
			reshareResult, err := reshares[id].GetResult()
			Expect(reshareResult).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrNotReady))
		}

		for _, r := range reshares {
			r.Start()
		}
		time.Sleep(1 * time.Second)

		// Stop Reshare process and update the share.
		for id, reshare := range reshares {
			reshare.Stop()
			reshareResult, err := reshare.GetResult()
			Expect(err).Should(BeNil())
			r.share[id] = reshareResult.Share
		}
		assertListener(listener, lens)

		By("Step 4: Signer again")
		for _, homoFunc := range homoFuncs {
			sign(homoFunc, int(threshold), lens, r, listener)
		}

		By("Step 5: Add new share")
		newPeerID := tss.GetTestID(lens)
		newPeerRank := uint32(0)

		var addShareForNew *newpeer.AddShare
		var addSharesForOld = make(map[string]*oldpeer.AddShare, lens)
		msgMain = make(map[string]types.MessageMain, lens+1)

		pmNew := tss.NewTestPeerManager(lens, lens+1)
		pmNew.Set(msgMain)
		listenerNew := new(mocks.StateChangedListener)
		listenerNew.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		addShareForNew = newpeer.NewAddShare(pmNew, r.publicKey, threshold, newPeerRank, listenerNew)
		msgMain[newPeerID] = addShareForNew
		addShareNewResult, err := addShareForNew.GetResult()
		Expect(addShareNewResult).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
		addShareForNew.Start()

		pmOlds := make([]types.PeerManager, lens)
		listenersOld := make([]*mocks.StateChangedListener, lens)
		for i := 0; i < lens; i++ {
			id := tss.GetTestID(i)
			pm := tss.NewTestPeerManager(i, lens)
			pm.Set(msgMain)
			pmOlds[i] = pm
			listenersOld[i] = new(mocks.StateChangedListener)
			listenersOld[i].On("OnStateChanged", types.StateInit, types.StateDone).Once()
			var err error
			addSharesForOld[id], err = oldpeer.NewAddShare(pmOlds[i], r.publicKey, threshold, r.share[id], r.bks, newPeerID, listenersOld[i])
			Expect(err).Should(BeNil())
			msgMain[id] = addSharesForOld[id]
			addShareOldResult, err := addSharesForOld[id].GetResult()
			Expect(addShareOldResult).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrNotReady))
		}

		// Send out all old peer message to new peer
		for _, fromA := range addSharesForOld {
			fromA.Start()
		}
		time.Sleep(1 * time.Second)

		// Stop add share process and check the result.
		for id, addshare := range addSharesForOld {
			addshare.Stop()
			addshareResult, err := addshare.GetResult()
			Expect(err).Should(BeNil())
			Expect(r.publicKey).Should(Equal(addshareResult.PublicKey))
			Expect(r.share[id]).Should(Equal(addshareResult.Share))
			Expect(r.bks[id]).Should(Equal(addshareResult.Bks[id]))
		}
		addShareForNew.Stop()
		addshareResult, err := addShareForNew.GetResult()
		Expect(err).Should(BeNil())
		Expect(r.publicKey).Should(Equal(addshareResult.PublicKey))
		Expect(addshareResult.Share).ShouldNot(BeNil())
		Expect(addshareResult.Bks[newPeerID]).ShouldNot(BeNil())
		// Update the new peer into result
		r.share[newPeerID] = addshareResult.Share
		r.bks[newPeerID] = addshareResult.Bks[newPeerID]

		for i := 0; i < lens; i++ {
			listenersOld[i].AssertExpectations(GinkgoT())
		}
		listenerNew.AssertExpectations(GinkgoT())
		assertListener(listener, lens)

		By("Step 6: Signer again")
		lens++
		listener = make([]*mocks.StateChangedListener, lens)
		for _, homoFunc := range homoFuncs {
			sign(homoFunc, int(threshold), lens, r, listener)
		}
	},
		Entry("S256 curve, 3 of (0,0,0,0,0)", elliptic.Secp256k1(), uint32(3), []uint32{0, 0, 0, 0, 0}),
		Entry("S256 curve, 3 of (0,0,0,1,1)", elliptic.Secp256k1(), uint32(3), []uint32{0, 0, 0, 1, 1}),
		Entry("S256 curve, 3 of (0,0,0)", elliptic.Secp256k1(), uint32(3), []uint32{0, 0, 0}),
	)
})

func sign(homoFunc func() (homo.Crypto, error), threshold, num int, dkgResult *result, listener []*mocks.StateChangedListener) {
	combination := combin.Combinations(num, threshold)
	msg := []byte{1, 2, 3}
	// Loop over all combinations.
	for _, c := range combination {
		signers := make(map[string]*signer.Signer, threshold)
		doneChs := make(map[string]chan struct{}, threshold)
		msgMain := make(map[string]types.MessageMain, threshold)
		for _, i := range c {
			h, err := homoFunc()
			Expect(err).Should(BeNil())
			id := tss.GetTestID(i)
			pm := tss.NewTestPeerManagerWithPeers(i, tss.GetTestPeersByArray(i, c))
			pm.Set(msgMain)
			doneChs[id] = make(chan struct{})
			doneCh := doneChs[id]
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateDone).Run(func(args mock.Arguments) {
				close(doneCh)
			}).Once()
			bks := make(map[string]*birkhoffinterpolation.BkParameter)
			bks[id] = dkgResult.bks[id]
			for _, j := range c {
				if i == j {
					continue
				}
				pID := tss.GetTestID(j)
				bks[pID] = dkgResult.bks[pID]
			}
			signers[id], err = signer.NewSigner(pm, dkgResult.publicKey, h, dkgResult.share[id], bks, msg, listener[i])
			Expect(err).Should(BeNil())
			msgMain[id] = signers[id]
			signerResult, err := signers[id].GetResult()
			Expect(signerResult).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrNotReady))
		}

		for _, s := range signers {
			s.Start()
		}

		for _, i := range c {
			id := tss.GetTestID(i)
			<-doneChs[id]
		}

		// Stop signer process and verify the signature.
		var r, s *big.Int
		for _, signer := range signers {
			signer.Stop()
			signerResult, err := signer.GetResult()
			Expect(err).Should(BeNil())
			// All R and S should be the same.
			if r != nil {
				Expect(r).Should(Equal(signerResult.R))
				Expect(s).Should(Equal(signerResult.S))
			} else {
				r = signerResult.R
				s = signerResult.S
			}
		}
		ecdsaPublicKey := &ecdsa.PublicKey{
			Curve: dkgResult.publicKey.GetCurve(),
			X:     dkgResult.publicKey.GetX(),
			Y:     dkgResult.publicKey.GetY(),
		}
		Expect(ecdsa.Verify(ecdsaPublicKey, msg, r, s)).Should(BeTrue())
		assertListener(listener, threshold)
	}
}

func assertListener(listener []*mocks.StateChangedListener, lens int) {
	for i := 0; i < lens; i++ {
		listener[i].AssertExpectations(GinkgoT())
	}
}

type result struct {
	publicKey *ecpointgrouplaw.ECPoint
	bks       map[string]*birkhoffinterpolation.BkParameter
	share     map[string]*big.Int
}
