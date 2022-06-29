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
	"errors"
	"time"

	mtaMocks "github.com/getamis/alice/crypto/mta/mocks"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("delta handler, negative cases", func() {
	var (
		peerId     = "peer-id"
		unknownErr = errors.New("unknown error")

		mockMta   *mtaMocks.Mta
		signers   map[string]*Signer
		listeners map[string]*mocks.StateChangedListener
	)
	BeforeEach(func() {
		signers, listeners = newTestSigners()
		// Override peer manager
		for _, s := range signers {
			p := newStopPeerManager(Type_Delta, s.ph.peerManager)
			s.ph.peerManager = p
		}

		for _, s := range signers {
			s.Start()
		}

		// Wait dkgs to handle decommit messages
		for _, s := range signers {
			for {
				_, ok := s.GetHandler().(*deltaHandler)
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

		mockMta = new(mtaMocks.Mta)
	})

	AfterEach(func() {
		for _, s := range signers {
			s.Stop()
		}
		time.Sleep(500 * time.Millisecond)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		mockMta.AssertExpectations(GinkgoT())
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*deltaHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})

		It("message is handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*deltaHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{
					delta: &deltaData{},
				}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
			}
		})

		It("message is not handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*deltaHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})
	})

	Context("HandleMessage", func() {
		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, s := range signers {
				Expect(s.GetHandler().HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})
	})

	Context("Finalize", func() {
		It("failed to get ai mta proof", func() {
			toId := tss.GetTestID(0)
			toS := signers[toId]
			toH, ok := toS.GetHandler().(*deltaHandler)
			Expect(ok).Should(BeTrue())

			for fromId, s := range signers {
				if toId == fromId {
					continue
				}
				fromH, ok := s.GetHandler().(*deltaHandler)
				Expect(ok).Should(BeTrue())
				Expect(toH.HandleMessage(log.Discard(), fromH.getDeltaMessage())).Should(BeNil())
			}

			toH.aiMta = mockMta
			mockMta.On("GetAProof", toH.getCurve()).Return(nil, unknownErr).Once()
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(unknownErr))
		})
	})
})
