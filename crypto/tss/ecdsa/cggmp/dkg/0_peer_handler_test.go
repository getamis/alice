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
package dkg

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types/mocks"
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

	Context("HandleMessage", func() {
		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			Expect(ph.HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
		})

		It("invalid x", func() {
			invalidBk := birkhoffinterpolation.NewBkParameter(big.NewInt(0), uint32(0))
			msg := &Message{
				Id:   peerId,
				Type: Type_Peer,
				Body: &Message_Peer{
					Peer: &BodyPeer{
						Bk: invalidBk.ToMessage(),
					},
				},
			}
			Expect(ph.HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
		})
	})

	Context("Finalize", func() {
		var (
			sid       = make([]byte, 1)
			curve     = elliptic.Secp256k1()
			threshold = uint32(3)
			ranks     = []uint32{0, 0, 0, 0, 0}

			dkgs      map[string]*DKG
			listeners map[string]*mocks.StateChangedListener
		)
		BeforeEach(func() {
			dkgs, listeners = newDKGs(curve, sid, threshold, ranks)
		})

		AfterEach(func() {
			for _, l := range listeners {
				l.AssertExpectations(GinkgoT())
			}
		})

		It("duplicate bks", func() {
			// time.Sleep(time.Second)
			// Add peer messages into dkg
			for selfId, selfD := range dkgs {
				for id, d := range dkgs {
					if selfId == id {
						continue
					}
					Expect(selfD.ph.HandleMessage(log.Discard(), d.ph.getPeerMessage())).Should(BeNil())
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
