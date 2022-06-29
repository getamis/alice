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

	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("decommit handler, negative cases", func() {
	var (
		dh     *decommitHandler
		peerId = "peer-id"
	)

	BeforeEach(func() {
		dh = newDecommitHandler(&peerHandler{
			peers: map[string]*peer{},
		})
	})
	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(dh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			dh.peers[peerId] = &peer{
				decommit: &decommitData{},
			}
			Expect(dh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			dh.peers[peerId] = &peer{}
			Expect(dh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})
	})

	Context("HandleMessage", func() {
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
				p := newStopPeerManager(Type_Decommit, d.ph.peerManager)
				d.ph.peerManager = p
			}
			for _, d := range dkgs {
				d.Start()
			}
			// Wait dkgs to handle decommit messages
			for _, d := range dkgs {
				for {
					_, ok := d.GetHandler().(*decommitHandler)
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

		It("invalid decommit message (different digest)", func() {
			var msg *Message
			for _, d := range dkgs {
				dh, ok := d.GetHandler().(*decommitHandler)
				Expect(ok).Should(BeTrue())

				if msg != nil {
					de := msg.GetDecommit()
					msg.Body = &Message_Decommit{
						Decommit: &BodyDecommit{
							HashDecommitment: &commitment.HashDecommitmentMessage{
								Data: []byte("invalid data"),
								Salt: de.HashDecommitment.Salt,
							},
							PointCommitment: de.PointCommitment,
						},
					}
					Expect(d.GetHandler().HandleMessage(log.Discard(), msg)).Should(Equal(commitment.ErrDifferentDigest))
				}
				msg = dh.getDecommitMessage()
			}
		})
	})
})

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
