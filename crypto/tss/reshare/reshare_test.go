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
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/tss/message/types/mocks"
	"github.com/getamis/alice/crypto/utils"
	proto "github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestReshare(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Reshare Suite")
}

var _ = Describe("Reshare", func() {
	curve := btcec.S256()
	DescribeTable("NewReshare()", func(c elliptic.Curve, threshold uint32, bks []*birkhoffinterpolation.BkParameter) {
		// new peer managers and reshares
		lens := len(bks)
		reshares := make(map[string]*Reshare, lens)
		peerManagers := make([]types.PeerManager, lens)
		bksMap := make(map[string]*birkhoffinterpolation.BkParameter)
		listener := make([]*mocks.StateChangedListener, lens)

		// Build old shares, and public key
		poly, err := polynomial.RandomPolynomial(c.Params().N, threshold-1)
		Expect(err).Should(BeNil())
		pubkey := ecpointgrouplaw.ScalarBaseMult(c, poly.Get(0))

		// Convert bks to map
		for i := 0; i < lens; i++ {
			id := getID(i)
			bksMap[id] = bks[i]
		}

		for i := 0; i < lens; i++ {
			id := getID(i)
			pm := newPeerManager(id, lens-1)
			pm.setReshares(reshares)
			peerManagers[i] = pm
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateDone).Once()
			tempPoly := poly.Differentiate(bks[i].GetRank())
			oldShare := tempPoly.Evaluate(bks[i].GetX())
			reshares[id], err = NewReshare(peerManagers[i], threshold, pubkey, oldShare, bksMap, listener[i])
			Expect(err).Should(BeNil())
			r, err := reshares[id].GetResult()
			Expect(r).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrNotReady))
			reshares[id].Start()
		}

		// Send out peer message
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

		for _, d := range reshares {
			d.Stop()
			_, err := d.GetResult()
			Expect(err).Should(BeNil())
		}

		for i := 0; i < lens; i++ {
			listener[i].AssertExpectations(GinkgoT())
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
			id := getID(i)
			bks[id] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
		}

		for i := 0; i < lens; i++ {
			id := getID(i)
			// Create one more peer deliberately
			pm := newPeerManager(id, lens)
			pm.setReshares(reshares)
			peerManagers[i] = pm
			listener[i] = new(mocks.StateChangedListener)
			listener[i].On("OnStateChanged", types.StateInit, types.StateFailed).Once()
			tempPoly := poly.Differentiate(ranks[i])
			oldShare := tempPoly.Evaluate(xs[i])
			reshares[id], err = NewReshare(peerManagers[i], threshold, pubkey, oldShare, bks, listener[i])
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
		reshares := make(map[string]*Reshare, lens)
		bks := make(map[string]*birkhoffinterpolation.BkParameter)
		listener := new(mocks.StateChangedListener)
		pubkey := ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(100))
		oldShare := big.NewInt(50)

		// Build bks
		for i := 0; i < lens; i++ {
			// Deliberately plus 1 to make bks[0] not found
			id := getID(i + 1)
			bks[id] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
		}

		id := getID(0)
		pm := newPeerManager(id, lens-1)
		pm.setReshares(reshares)
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
			id := getID(i)
			bks[id] = birkhoffinterpolation.NewBkParameter(xs[i], ranks[i])
		}

		for i := 0; i < lens; i++ {
			id := getID(i)
			pm := newPeerManager(id, lens-1)
			pm.setReshares(reshares)
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

func getID(id int) string {
	return fmt.Sprintf("id-%d", id)
}

type peerManager struct {
	id       string
	numPeers uint32
	reshares map[string]*Reshare
}

func newPeerManager(id string, numPeers int) *peerManager {
	return &peerManager{
		id:       id,
		numPeers: uint32(numPeers),
	}
}

func (p *peerManager) setReshares(reshares map[string]*Reshare) {
	p.reshares = reshares
}

func (p *peerManager) NumPeers() uint32 {
	return p.numPeers
}

func (p *peerManager) SelfID() string {
	return p.id
}

func (p *peerManager) MustSend(id string, message proto.Message) {
	d := p.reshares[id]
	msg := message.(types.Message)
	Expect(d.AddMessage(msg)).Should(BeNil())
}
