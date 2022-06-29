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
package signer

import (
	"time"

	"github.com/getamis/alice/crypto/elliptic"

	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("decommit vi ai handler, negative cases", func() {
	var (
		peerId = "peer-id"

		signers   map[string]*Signer
		listeners map[string]*mocks.StateChangedListener
	)
	BeforeEach(func() {
		signers, listeners = newTestSigners()
		// Override peer manager
		for _, s := range signers {
			p := newStopPeerManager(Type_DecommitViAi, s.ph.peerManager)
			s.ph.peerManager = p
		}

		for _, s := range signers {
			s.Start()
		}

		// Wait dkgs to handle decommit messages
		for _, s := range signers {
			for {
				_, ok := s.GetHandler().(*decommitViAiHandler)
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
		for _, s := range signers {
			s.Stop()
		}
		time.Sleep(500 * time.Millisecond)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*decommitViAiHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})

		It("message is handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*decommitViAiHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{
					decommitViAi: &decommitViAiData{},
				}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
			}
		})

		It("message is not handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*decommitViAiHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})
	})

	Context("HandleMessage", func() {
		var fromH, toH *decommitViAiHandler
		var msg *Message
		BeforeEach(func() {
			var ok bool
			fromId := tss.GetTestID(1)
			fromS := signers[fromId]
			fromH, ok = fromS.GetHandler().(*decommitViAiHandler)
			Expect(ok).Should(BeTrue())

			toId := tss.GetTestID(0)
			toS := signers[toId]
			toH, ok = toS.GetHandler().(*decommitViAiHandler)
			Expect(ok).Should(BeTrue())

			msg = fromH.getDecommitAiViMessage()
		})

		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, s := range signers {
				Expect(s.GetHandler().HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})

		It("failed to verify li", func() {
			msg := fromH.getDecommitAiViMessage()
			newMsg := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_DecommitViAi{
					DecommitViAi: &BodyDecommitViAi{
						AiDecommitment: msg.GetDecommitViAi().GetAiDecommitment(),
						ViDecommitment: msg.GetDecommitViAi().GetViDecommitment(),
						LiProof:        &zkproof.SchnorrProofMessage{},
						RhoIProof:      msg.GetDecommitViAi().GetRhoIProof(),
					},
				},
			}
			Expect(toH.HandleMessage(log.Discard(), newMsg)).Should(Equal(pt.ErrInvalidPoint))
		})

		It("failed to verify RhoIProof", func() {
			newMsg := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_DecommitViAi{
					DecommitViAi: &BodyDecommitViAi{
						AiDecommitment: msg.GetDecommitViAi().GetAiDecommitment(),
						ViDecommitment: msg.GetDecommitViAi().GetViDecommitment(),
						LiProof:        msg.GetDecommitViAi().GetLiProof(),
						RhoIProof:      &zkproof.SchnorrProofMessage{},
					},
				},
			}
			Expect(toH.HandleMessage(log.Discard(), newMsg)).Should(Equal(pt.ErrInvalidPoint))
		})

		It("failed to verify RhoIProof", func() {
			msg := fromH.getDecommitAiViMessage()
			newMsg := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_DecommitViAi{
					DecommitViAi: &BodyDecommitViAi{
						AiDecommitment: msg.GetDecommitViAi().GetAiDecommitment(),
						ViDecommitment: msg.GetDecommitViAi().GetViDecommitment(),
						LiProof:        msg.GetDecommitViAi().GetLiProof(),
						RhoIProof:      &zkproof.SchnorrProofMessage{},
					},
				},
			}
			Expect(toH.HandleMessage(log.Discard(), newMsg)).Should(Equal(pt.ErrInvalidPoint))
		})

		It("failed to decommit vi", func() {
			msg := fromH.getDecommitAiViMessage()
			newMsg := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_DecommitViAi{
					DecommitViAi: &BodyDecommitViAi{
						AiDecommitment: msg.GetDecommitViAi().GetAiDecommitment(),
						ViDecommitment: &commitment.HashDecommitmentMessage{},
						LiProof:        msg.GetDecommitViAi().GetLiProof(),
						RhoIProof:      msg.GetDecommitViAi().GetRhoIProof(),
					},
				},
			}
			Expect(toH.HandleMessage(log.Discard(), newMsg)).Should(Equal(commitment.ErrDifferentDigest))
		})

		It("failed to decommit ai", func() {
			msg := fromH.getDecommitAiViMessage()
			newMsg := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_DecommitViAi{
					DecommitViAi: &BodyDecommitViAi{
						AiDecommitment: &commitment.HashDecommitmentMessage{},
						ViDecommitment: msg.GetDecommitViAi().GetViDecommitment(),
						LiProof:        msg.GetDecommitViAi().GetLiProof(),
						RhoIProof:      msg.GetDecommitViAi().GetRhoIProof(),
					},
				},
			}
			Expect(toH.HandleMessage(log.Discard(), newMsg)).Should(Equal(commitment.ErrDifferentDigest))
		})
	})

	Context("Finalize", func() {
		var toH *decommitViAiHandler
		BeforeEach(func() {
			var ok bool
			toId := tss.GetTestID(0)
			toS := signers[toId]
			toH, ok = toS.GetHandler().(*decommitViAiHandler)
			Expect(ok).Should(BeTrue())

			for fromId, s := range signers {
				if toId == fromId {
					continue
				}
				fromH, ok := s.GetHandler().(*decommitViAiHandler)
				Expect(ok).Should(BeTrue())
				Expect(toH.HandleMessage(log.Discard(), fromH.getDecommitAiViMessage())).Should(BeNil())
			}
		})

		It("failed to build V (different curve)", func() {
			toH.vi = pt.NewBase(elliptic.Ed25519())
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(pt.ErrDifferentCurve))
		})

		It("failed to build A (different curve)", func() {
			toH.ai = pt.NewBase(elliptic.Ed25519())
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(pt.ErrDifferentCurve))
		})

	})
})
