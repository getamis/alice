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

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/matrix"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("commit handler, negative cases", func() {
	var (
		ph *commitHandler

		peerId = "peer-id"
	)

	BeforeEach(func() {
		ph = &commitHandler{
			peers: map[string]*peer{},
		}
	})

	Context("newCommitHandler", func() {
		var (
			mockPeerManager *mocks.PeerManager

			curve = elliptic.Secp256k1()
			bks   = map[string]*birkhoffinterpolation.BkParameter{
				"1": birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				"2": birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				"3": birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
				"4": birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0)),
				"5": birkhoffinterpolation.NewBkParameter(big.NewInt(5), uint32(0)),
			}
			gScale    = big.NewInt(5987)
			expPublic = ecpointgrouplaw.ScalarBaseMult(curve, gScale)
			// unknownErr = errors.New("unknown error")
			threshold = uint32(3)
		)
		BeforeEach(func() {
			mockPeerManager = new(mocks.PeerManager)
		})
		AfterEach(func() {
			mockPeerManager.AssertExpectations(GinkgoT())
		})

		It("inconsistent peer number and bks", func() {
			mockPeerManager.On("NumPeers").Return(uint32(3)).Once()
			got, err := newCommitHandler(expPublic, mockPeerManager, threshold, nil, bks)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrInconsistentPeerNumAndBks))
		})

		It("invalid threshold", func() {
			mockPeerManager.On("NumPeers").Return(uint32(4)).Once()
			got, err := newCommitHandler(expPublic, mockPeerManager, 6, nil, bks)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(utils.ErrLargeThreshold))
		})

		It("self id not found", func() {
			mockPeerManager.On("NumPeers").Return(uint32(4)).Once()
			mockPeerManager.On("SelfID").Return("not found").Once()
			got, err := newCommitHandler(expPublic, mockPeerManager, 5, nil, bks)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrSelfBKNotFound))
		})

		It("duplicate bks", func() {
			dupBks := map[string]*birkhoffinterpolation.BkParameter{
				"1": birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
				"2": birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
				"3": birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
				"4": birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0)),
				"5": birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0)),
			}
			mockPeerManager.On("NumPeers").Return(uint32(4)).Once()
			mockPeerManager.On("SelfID").Return("1").Once()
			got, err := newCommitHandler(expPublic, mockPeerManager, 5, nil, dupBks)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(matrix.ErrNotInvertableMatrix))
		})
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			ph.peers[peerId] = &peer{
				commit: &commitData{},
			}
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})
	})

	Context("HandleMessage/Finalize", func() {
		var (
			reshares  map[string]*Reshare
			listeners map[string]*mocks.StateChangedListener
		)
		BeforeEach(func() {
			reshares, listeners = newTestReshares()
		})

		AfterEach(func() {
			for _, l := range listeners {
				l.AssertExpectations(GinkgoT())
			}
		})

		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, r := range reshares {
				Expect(r.ch.HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})
	})
})

func newTestReshares() (map[string]*Reshare, map[string]*mocks.StateChangedListener) {
	curve := elliptic.Secp256k1()
	bks := []*birkhoffinterpolation.BkParameter{
		birkhoffinterpolation.NewBkParameter(big.NewInt(1), uint32(0)),
		birkhoffinterpolation.NewBkParameter(big.NewInt(2), uint32(0)),
		birkhoffinterpolation.NewBkParameter(big.NewInt(3), uint32(0)),
		birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0)),
		birkhoffinterpolation.NewBkParameter(big.NewInt(5), uint32(1)),
	}
	return newReshares(curve, uint32(5), bks)
}

type stopPeerManager struct {
	types.PeerManager

	stopMessageType Type
	isStopped       bool
}

func newStopPeerManager(stopMessageType Type, p types.PeerManager) *stopPeerManager {
	return &stopPeerManager{
		PeerManager:     p,
		stopMessageType: stopMessageType,
		isStopped:       false,
	}
}

func (p *stopPeerManager) MustSend(id string, message interface{}) {
	if p.isStopped {
		return
	}

	// Stop peer manager if we try to send the next
	msg := message.(*Message)
	if msg.Type >= p.stopMessageType {
		p.isStopped = true
		return
	}
	p.PeerManager.MustSend(id, message)
}
