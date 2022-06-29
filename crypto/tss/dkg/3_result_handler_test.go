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

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/matrix"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("result handler, negative cases", func() {
	var (
		rh     *resultHandler
		peerId = "peer-id"
	)

	BeforeEach(func() {
		rh = &resultHandler{
			verifyHandler: &verifyHandler{
				decommitHandler: &decommitHandler{
					peerHandler: &peerHandler{
						peers: map[string]*peer{},
					},
				},
			},
		}
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			rh.peers[peerId] = &peer{
				result: &resultData{},
			}
			Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			rh.peers[peerId] = &peer{}
			Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
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
				p := newStopPeerManager(Type_Result, d.ph.peerManager)
				d.ph.peerManager = p
			}

			for _, d := range dkgs {
				d.Start()
			}

			// Wait dkgs to handle result messages
			for _, d := range dkgs {
				for {
					_, ok := d.GetHandler().(*resultHandler)
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

		It("invalid V", func() {
			var msg *Message
			for _, d := range dkgs {
				rh, ok := d.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())

				if msg != nil {
					Expect(rh.HandleMessage(log.Discard(), msg)).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
				}
				msg = rh.getResultMessage()
				r := msg.GetResult()
				r.SiGProofMsg.V.X = []byte("invalid X")
				msg.Body = &Message_Result{
					Result: r,
				}
			}
		})

		It("invalid verify", func() {
			var msg *Message
			for _, d := range dkgs {
				rh, ok := d.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())

				if msg != nil {
					Expect(rh.HandleMessage(log.Discard(), msg)).Should(Equal(zkproof.ErrVerifyFailure))
				}
				msg = rh.getResultMessage()
				r := msg.GetResult()
				r.SiGProofMsg.U = []byte("invalid U")
				msg.Body = &Message_Result{
					Result: r,
				}
			}
		})

		It("invalid self V", func() {
			for _, d := range dkgs {
				rh, ok := d.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())

				rh.siGProofMsg.V.X = []byte("invalid X")
				h, err := rh.Finalize(log.Discard())
				Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
				Expect(h).Should(BeNil())
			}
		})

		It("0 threshold", func() {
			for _, d := range dkgs {
				rh, ok := d.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())

				rh.threshold = 0
				for _, peer := range rh.peers {
					// empty result data
					peer.result = &resultData{}
				}
				h, err := rh.Finalize(log.Discard())
				Expect(err).Should(Equal(matrix.ErrZeroColumns))
				Expect(h).Should(BeNil())
			}
		})

		It("failed to calculate public key", func() {
			for _, d := range dkgs {
				rh, ok := d.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())

				for _, peer := range rh.peers {
					peer.result = &resultData{
						result: ecpointgrouplaw.NewBase(elliptic.Ed25519()),
					}
				}
				h, err := rh.Finalize(log.Discard())
				Expect(err).Should(Equal(ecpointgrouplaw.ErrDifferentCurve))
				Expect(h).Should(BeNil())
			}
		})

		It("inconsistent public key", func() {
			for _, d := range dkgs {
				rh, ok := d.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())

				for _, peer := range rh.peers {
					peer.result = &resultData{
						result: ecpointgrouplaw.NewBase(elliptic.Secp256k1()),
					}
				}
				h, err := rh.Finalize(log.Discard())
				Expect(err).Should(Equal(tss.ErrInconsistentPubKey))
				Expect(h).Should(BeNil())
			}
		})
	})
})
