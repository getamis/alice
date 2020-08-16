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

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/tss/message/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("peer handler, negative cases", func() {
	var (
		ph     *peerHandler
		peerId = "peer-id"
	)

	BeforeEach(func() {
		ph = &peerHandler{
			peers: map[string]*peer{},
		}
	})
	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			ph.peers[peerId] = &peer{
				peer: &peerData{},
			}
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})
	})

	Context("Finalize", func() {
		var (
			curve     = btcec.S256()
			threshold = uint32(3)
			ranks     = []uint32{0, 0, 0, 0, 0}

			dkgs      map[string]*DKG
			listeners map[string]*mocks.StateChangedListener
		)
		BeforeEach(func() {
			dkgs, listeners = newDKGs(curve, threshold, ranks)
		})

		AfterEach(func() {
			for _, l := range listeners {
				l.On("OnStateChanged", types.StateInit, types.StateFailed).Return().Once()
			}
			for _, d := range dkgs {
				d.Stop()
			}
			time.Sleep(500 * time.Millisecond)
			for _, l := range listeners {
				l.AssertExpectations(GinkgoT())
			}
		})

		It("duplicate bks", func() {
			// Add peer messages into dkg
			for selfId, selfD := range dkgs {
				for id, d := range dkgs {
					if selfId == id {
						continue
					}
					Expect(selfD.ph.HandleMessage(log.Discard(), d.GetPeerMessage())).Should(BeNil())
				}
			}

			for _, d := range dkgs {
				// Make duplicate bk
				for _, p := range d.ph.peers {
					p.peer.bk = d.ph.bk
					break
				}
				got, err := d.ph.Finalize(log.Discard())
				Expect(got).Should(BeNil())
				Expect(err).Should(Equal(birkhoffinterpolation.ErrInvalidBks))
			}
		})
	})
})
