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
	"crypto/elliptic"
	"time"

	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/tss/message/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("decommit ui ti handler, negative cases", func() {
	var (
		peerId = "peer-id"

		signers   map[string]*Signer
		listeners map[string]*mocks.StateChangedListener
	)
	BeforeEach(func() {
		signers, listeners = newTestSigners()
		// Override peer manager
		for _, s := range signers {
			p := newStopPeerManager(Type_DecommitUiTi, s.ph.peerManager)
			s.ph.peerManager = p
		}

		// Send out peer message
		for fromID, fromD := range signers {
			msg := fromD.ph.GetPubkeyMessage()
			for toID, toD := range signers {
				if fromID == toID {
					continue
				}
				Expect(toD.AddMessage(msg)).Should(BeNil())
			}
		}
		// Wait dkgs to handle decommit messages
		for _, s := range signers {
			_, ok := s.GetHandler().(*decommitUiTiHandler)
			if !ok {
				time.Sleep(500 * time.Millisecond)
			}
		}
	})

	AfterEach(func() {
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateFailed).Return().Once()
		}
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
				rh, ok := s.GetHandler().(*decommitUiTiHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})

		It("message is handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*decommitUiTiHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{
					decommitUiTi: &decommitUiTiData{},
				}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
			}
		})

		It("message is not handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*decommitUiTiHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})
	})

	Context("HandleMessage", func() {
		var fromH, toH *decommitUiTiHandler
		var msg *Message
		BeforeEach(func() {
			var ok bool
			fromId := getID(1)
			fromS := signers[fromId]
			fromH, ok = fromS.GetHandler().(*decommitUiTiHandler)
			Expect(ok).Should(BeTrue())

			toId := getID(0)
			toS := signers[toId]
			toH, ok = toS.GetHandler().(*decommitUiTiHandler)
			Expect(ok).Should(BeTrue())

			msg = fromH.getDecommitUiTiMessage()
		})

		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, s := range signers {
				Expect(s.GetHandler().HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})

		It("failed to decommit ui", func() {
			newMsg := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_DecommitUiTi{
					DecommitUiTi: &BodyDecommitUiTi{
						UiDecommitment: &commitment.HashDecommitmentMessage{},
						TiDecommitment: msg.GetDecommitUiTi().GetTiDecommitment(),
					},
				},
			}
			Expect(toH.HandleMessage(log.Discard(), newMsg)).Should(Equal(commitment.ErrDifferentDigest))
		})

		It("failed to decommit ti", func() {
			newMsg := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_DecommitUiTi{
					DecommitUiTi: &BodyDecommitUiTi{
						UiDecommitment: msg.GetDecommitUiTi().GetUiDecommitment(),
						TiDecommitment: &commitment.HashDecommitmentMessage{},
					},
				},
			}
			Expect(toH.HandleMessage(log.Discard(), newMsg)).Should(Equal(commitment.ErrDifferentDigest))
		})
	})

	Context("Finalize", func() {
		var toH *decommitUiTiHandler
		BeforeEach(func() {
			var ok bool
			toId := getID(0)
			toS := signers[toId]
			toH, ok = toS.GetHandler().(*decommitUiTiHandler)
			Expect(ok).Should(BeTrue())

			for fromId, s := range signers {
				if toId == fromId {
					continue
				}
				fromH, ok := s.GetHandler().(*decommitUiTiHandler)
				Expect(ok).Should(BeTrue())
				Expect(toH.HandleMessage(log.Discard(), fromH.getDecommitUiTiMessage())).Should(BeNil())
			}
		})

		It("failed to build U (different curve)", func() {
			toH.ui = pt.NewBase(elliptic.P224())
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(pt.ErrDifferentCurve))
		})

		It("failed to build T (different curve)", func() {
			toH.ti = pt.NewBase(elliptic.P224())
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(pt.ErrDifferentCurve))
		})
	})
})
