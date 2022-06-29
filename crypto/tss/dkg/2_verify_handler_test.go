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
	"time"

	"github.com/getamis/alice/crypto/elliptic"

	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("verify handler, negative cases", func() {
	var (
		vh     *verifyHandler
		peerId = "peer-id"
	)

	BeforeEach(func() {
		vh = &verifyHandler{
			decommitHandler: &decommitHandler{
				peerHandler: &peerHandler{
					peers: map[string]*peer{},
				},
			},
		}
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(vh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			vh.peers[peerId] = &peer{
				verify: &verifyData{},
			}
			Expect(vh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			vh.peers[peerId] = &peer{}
			Expect(vh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})
	})

	Context("HandleMessage/Finalize", func() {
		var (
			curve     = elliptic.Secp256k1()
			threshold = uint32(3)
			ranks     = []uint32{0, 0, 0, 0, 0}

			dkgs      map[string]*DKG
			listeners map[string]*mocks.StateChangedListener
		)
		BeforeEach(func() {
			dkgs, listeners = newDKGs(curve, threshold, ranks)
			// Override peer manager
			for _, d := range dkgs {
				p := newStopPeerManager(Type_Verify, d.ph.peerManager)
				d.ph.peerManager = p
			}
			for _, d := range dkgs {
				d.Start()
			}
			// Ensure all handlers are verify handlers
			for _, d := range dkgs {
				for {
					_, ok := d.GetHandler().(*verifyHandler)
					if !ok {
						time.Sleep(500 * time.Millisecond)
						continue
					}
					break
				}
			}
			for _, l := range listeners {
				l.On("OnStateChanged", types.StateInit, types.StateFailed).Return().Once()
			}
		})

		AfterEach(func() {
			for _, d := range dkgs {
				d.Stop()
			}
			time.Sleep(500 * time.Millisecond)
			for _, l := range listeners {
				l.AssertExpectations(GinkgoT())
			}
		})

		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, d := range dkgs {
				Expect(d.GetHandler().HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})

		It("invalid verify message", func() {
			for _, d := range dkgs {
				vh, ok := d.GetHandler().(*verifyHandler)
				Expect(ok).Should(BeTrue())

				for pId, peer := range vh.peers {
					vm := peer.decommit.verifyMessage
					vm.Id = pId
					Expect(vh.HandleMessage(log.Discard(), vm)).Should(Equal(commitment.ErrFailedVerify))
				}
			}
		})

		It("failed to sum u0g", func() {
			for _, d := range dkgs {
				vh, ok := d.GetHandler().(*verifyHandler)
				Expect(ok).Should(BeTrue())

				vh.u0g = ecpointgrouplaw.NewBase(elliptic.Ed25519())
				h, err := vh.Finalize(log.Discard())
				Expect(err).Should(Equal(ecpointgrouplaw.ErrDifferentCurve))
				Expect(h).Should(BeNil())
			}
		})
	})
})
