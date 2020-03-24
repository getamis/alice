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
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/tss/message/types/mocks"
	"github.com/getamis/alice/crypto/tss/reshare"
	"github.com/getamis/alice/crypto/tss/signer"
	"github.com/golang/protobuf/proto"
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
		dkgPeerManagers := make([]types.PeerManager, lens)
		for i := 0; i < lens; i++ {
			id := getID(i)
			pm := newDKGPeerManager(id, lens-1)
			pm.setDKGs(dkgs)
			dkgPeerManagers[i] = pm
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateDone).Once()
			var err error
			dkgs[id], err = dkg.NewDKG(c, dkgPeerManagers[i], threshold, ranks[i], listener[i])
			Expect(err).Should(BeNil())
			dkgResult, err := dkgs[id].GetResult()
			Expect(dkgResult).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrNotReady))
			dkgs[id].Start()
		}

		// Send out peer message
		for fromID, fromD := range dkgs {
			msg := fromD.GetPeerMessage()
			for toID, toD := range dkgs {
				if fromID == toID {
					continue
				}
				Expect(toD.AddMessage(msg)).Should(BeNil())
			}
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

		By("Step 2: Signer")
		for _, homoFunc := range homoFuncs {
			sign(homoFunc, int(threshold), lens, r, listener)
		}

		By("Step 3: Reshare")
		reshares := make(map[string]*reshare.Reshare, lens)
		resharePeerManagers := make([]types.PeerManager, lens)
		for i := 0; i < lens; i++ {
			id := getID(i)
			pm := newResharePeerManager(id, lens-1)
			pm.setReshares(reshares)
			resharePeerManagers[i] = pm
			listener[i].On("OnStateChanged", types.StateInit, types.StateDone).Once()
			var err error
			reshares[id], err = reshare.NewReshare(resharePeerManagers[i], threshold, r.publicKey, r.share[id], r.bks, listener[i])
			Expect(err).Should(BeNil())
			reshareResult, err := reshares[id].GetResult()
			Expect(reshareResult).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrNotReady))
			reshares[id].Start()
		}

		// Send out commit message
		for fromID, fromD := range reshares {
			msg := fromD.GetCommitMessage()
			for toID, toD := range reshares {
				if fromID == toID {
					continue
				}
				Expect(toD.AddMessage(msg)).Should(BeNil())
			}
		}
		time.Sleep(1 * time.Second)

		// Stop Reshare process and update the share.
		for id, reshare := range reshares {
			reshare.Stop()
			reshareResult, err := reshare.GetResult()
			Expect(err).Should(BeNil())
			r.share[id] = reshareResult.Share
		}

		By("Step 4: Signer again")
		for _, homoFunc := range homoFuncs {
			sign(homoFunc, int(threshold), lens, r, listener)
		}

		// Assert the outcome of listener is expected.
		for i := 0; i < lens; i++ {
			listener[i].AssertExpectations(GinkgoT())
		}
	},
		Entry("P224 curve, 3 of (0,0,0)", elliptic.P224(), uint32(3), []uint32{0, 0, 0}),
		Entry("P256 curve, 3 of (0,0,0)", elliptic.P256(), uint32(3), []uint32{0, 0, 0}),
		Entry("P384 curve, 3 of (0,0,0)", elliptic.P384(), uint32(3), []uint32{0, 0, 0}),
		Entry("S256 curve, 3 of (0,0,0,0,0)", btcec.S256(), uint32(3), []uint32{0, 0, 0, 0, 0}),
		Entry("S256 curve, 3 of (0,0,0,1,1)", btcec.S256(), uint32(3), []uint32{0, 0, 0, 1, 1}),
		Entry("S256 curve, 3 of (0,0,0)", btcec.S256(), uint32(3), []uint32{0, 0, 0}),
	)
})

func sign(homoFunc func() (homo.Crypto, error), threshold, num int, dkgResult *result, listener []*mocks.StateChangedListener) {
	combination := combin.Combinations(num, threshold)
	msg := []byte{1, 2, 3}
	// Loop over all combinations.
	for _, c := range combination {
		signers := make(map[string]*signer.Signer, threshold)
		doneChs := make(map[string]chan struct{}, threshold)
		for _, i := range c {
			h, err := homoFunc()
			Expect(err).Should(BeNil())
			id := getID(i)
			pm := newSignerPeerManager(id, threshold-1)
			pm.setSigners(signers)
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
				pId := getID(j)
				bks[pId] = dkgResult.bks[pId]
			}
			signers[id], err = signer.NewSigner(pm, dkgResult.publicKey, h, dkgResult.share[id], bks, msg, listener[i])
			Expect(err).Should(BeNil())
			signerResult, err := signers[id].GetResult()
			Expect(signerResult).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrNotReady))
			signers[id].Start()
		}

		// Send out pubkey message.
		for fromID, fromD := range signers {
			msg := fromD.GetPubkeyMessage()
			for toID, toD := range signers {
				if fromID == toID {
					continue
				}
				Expect(toD.AddMessage(msg)).Should(BeNil())
			}
		}

		for _, i := range c {
			id := getID(i)
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
	}
}

type result struct {
	publicKey *ecpointgrouplaw.ECPoint
	bks       map[string]*birkhoffinterpolation.BkParameter
	share     map[string]*big.Int
}

func getID(id int) string {
	return fmt.Sprintf("id-%d", id)
}

type dkgPeerManager struct {
	id       string
	numPeers uint32
	dkgs     map[string]*dkg.DKG
}

func newDKGPeerManager(id string, numPeers int) *dkgPeerManager {
	return &dkgPeerManager{
		id:       id,
		numPeers: uint32(numPeers),
	}
}

func (p *dkgPeerManager) setDKGs(dkgs map[string]*dkg.DKG) {
	p.dkgs = dkgs
}

func (p *dkgPeerManager) NumPeers() uint32 {
	return p.numPeers
}

func (p *dkgPeerManager) SelfID() string {
	return p.id
}

func (p *dkgPeerManager) MustSend(id string, message proto.Message) {
	d := p.dkgs[id]
	msg := message.(types.Message)
	Expect(d.AddMessage(msg)).Should(BeNil())
}

type signerPeerManager struct {
	id       string
	numPeers uint32
	signers  map[string]*signer.Signer
}

func newSignerPeerManager(id string, numPeers int) *signerPeerManager {
	return &signerPeerManager{
		id:       id,
		numPeers: uint32(numPeers),
	}
}

func (p *signerPeerManager) setSigners(signers map[string]*signer.Signer) {
	p.signers = signers
}

func (p *signerPeerManager) NumPeers() uint32 {
	return p.numPeers
}

func (p *signerPeerManager) SelfID() string {
	return p.id
}

func (p *signerPeerManager) MustSend(id string, message proto.Message) {
	d := p.signers[id]
	msg := message.(types.Message)
	Expect(d.AddMessage(msg)).Should(BeNil())
}

type resharePeerManager struct {
	id       string
	numPeers uint32
	reshares map[string]*reshare.Reshare
}

func newResharePeerManager(id string, numPeers int) *resharePeerManager {
	return &resharePeerManager{
		id:       id,
		numPeers: uint32(numPeers),
	}
}

func (p *resharePeerManager) setReshares(reshares map[string]*reshare.Reshare) {
	p.reshares = reshares
}

func (p *resharePeerManager) NumPeers() uint32 {
	return p.numPeers
}

func (p *resharePeerManager) SelfID() string {
	return p.id
}

func (p *resharePeerManager) MustSend(id string, message proto.Message) {
	d := p.reshares[id]
	msg := message.(types.Message)
	Expect(d.AddMessage(msg)).Should(BeNil())
}
