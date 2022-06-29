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
	"math/big"
	"time"

	mtaMocks "github.com/getamis/alice/crypto/mta/mocks"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("enck handler, negative cases", func() {
	var (
		peerId     = "peer-id"
		unknownErr = errors.New("unknown error")

		signers   map[string]*Signer
		listeners map[string]*mocks.StateChangedListener
	)
	BeforeEach(func() {
		signers, listeners = newTestSigners()
		// Override peer manager
		for _, s := range signers {
			p := newStopPeerManager(Type_EncK, s.ph.peerManager)
			s.ph.peerManager = p
		}

		for _, s := range signers {
			s.Start()
		}
		// Wait dkgs to handle decommit messages
		for _, s := range signers {
			for {
				_, ok := s.GetHandler().(*encKHandler)
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

	Context("newEncKHandler", func() {
		It("failed to override a", func() {
			wi := big.NewInt(100)
			mockMta := new(mtaMocks.Mta)
			defer func() {
				mockMta.AssertExpectations(GinkgoT())
			}()
			mockMta.On("OverrideA", wi).Return(nil, unknownErr).Once()
			got, err := newEncKHandler(&pubkeyHandler{
				wi:    wi,
				aiMta: mockMta,
			})
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(unknownErr))
		})
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*encKHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})

		It("message is handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*encKHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{
					enck: &encKData{},
				}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
			}
		})

		It("message is not handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*encKHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})
	})

	Context("HandleMessage", func() {
		var fromId string
		var fromH, toH *encKHandler
		var msg *Message
		var mockMta *mtaMocks.Mta
		BeforeEach(func() {
			mockMta = new(mtaMocks.Mta)

			var ok bool
			fromId = tss.GetTestID(1)
			fromS := signers[fromId]
			fromH, ok = fromS.GetHandler().(*encKHandler)
			Expect(ok).Should(BeTrue())
			msg = fromH.getEnckMessage()

			toId := tss.GetTestID(0)
			toS := signers[toId]
			toH, ok = toS.GetHandler().(*encKHandler)
			Expect(ok).Should(BeTrue())
		})

		AfterEach(func() {
			mockMta.AssertExpectations(GinkgoT())
		})
		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, s := range signers {
				Expect(s.GetHandler().HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})

		It("failed to compute ai mta", func() {
			toH.aiMta = mockMta
			mockMta.On("Compute", toH.peers[fromId].pubkey.publicKey, msg.GetEncK().GetEnck()).Return(nil, nil, unknownErr).Once()
			err := toH.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(unknownErr))
		})

		It("failed to compute wi mta", func() {
			toH.wiMta = mockMta
			mockMta.On("Compute", toH.peers[fromId].pubkey.publicKey, msg.GetEncK().GetEnck()).Return(nil, nil, unknownErr).Once()
			err := toH.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(unknownErr))
		})

		It("failed to compute wi GetProofWithCheck", func() {
			toH.wiMta = mockMta
			wiBeta := big.NewInt(101)
			mockMta.On("Compute", toH.peers[fromId].pubkey.publicKey, msg.GetEncK().GetEnck()).Return(big.NewInt(100), wiBeta, nil).Once()
			mockMta.On("GetProofWithCheck", toH.getCurve(), wiBeta).Return(nil, unknownErr).Once()
			err := toH.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(unknownErr))
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
