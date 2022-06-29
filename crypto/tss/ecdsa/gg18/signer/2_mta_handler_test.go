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

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	mtaMocks "github.com/getamis/alice/crypto/mta/mocks"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("mta handler, negative cases", func() {
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
			p := newStopPeerManager(Type_Mta, s.ph.peerManager)
			s.ph.peerManager = p
		}

		for _, s := range signers {
			s.Start()
		}
		// Wait dkgs to handle decommit messages
		for _, s := range signers {
			for {
				_, ok := s.GetHandler().(*mtaHandler)
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
				rh, ok := s.GetHandler().(*mtaHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})

		It("message is handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*mtaHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{
					mta: &mtaData{},
				}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
			}
		})

		It("message is not handled before", func() {
			for _, s := range signers {
				rh, ok := s.GetHandler().(*mtaHandler)
				Expect(ok).Should(BeTrue())
				s.ph.peers[peerId] = &peer{}
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})
	})

	Context("HandleMessage", func() {
		var toId string
		var fromH, toH *mtaHandler
		BeforeEach(func() {
			var ok bool
			fromId := tss.GetTestID(1)
			fromS := signers[fromId]
			fromH, ok = fromS.GetHandler().(*mtaHandler)
			Expect(ok).Should(BeTrue())

			toId = tss.GetTestID(0)
			toS := signers[toId]
			toH, ok = toS.GetHandler().(*mtaHandler)
			Expect(ok).Should(BeTrue())
		})

		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, s := range signers {
				Expect(s.GetHandler().HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})

		It("failed to decrypt ai mta", func() {
			toH.aiMta = mockMta
			msg := fromH.peers[toId].enck.mtaMsg
			mockMta.On("Decrypt", new(big.Int).SetBytes(msg.GetMta().EncAiAlpha)).Return(nil, unknownErr).Once()
			err := toH.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(unknownErr))
		})

		It("failed to decrypt wi mta", func() {
			toH.wiMta = mockMta
			msg := fromH.peers[toId].enck.mtaMsg
			mockMta.On("Decrypt", new(big.Int).SetBytes(msg.GetMta().EncWiAlpha)).Return(nil, unknownErr).Once()
			err := toH.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(unknownErr))
		})

		It("failed to decrypt wi verify check", func() {
			toH.wiMta = mockMta
			msg := fromH.peers[toId].enck.mtaMsg
			wiAlpha := big.NewInt(101)
			mockMta.On("Decrypt", new(big.Int).SetBytes(msg.GetMta().EncWiAlpha)).Return(wiAlpha, nil).Once()
			mockMta.On("VerifyProofWithCheck", msg.GetMta().WiProof, toH.getCurve(), wiAlpha).Return(nil, unknownErr).Once()
			err := toH.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(unknownErr))
		})
	})

	Context("Finalize", func() {
		var toH *mtaHandler
		BeforeEach(func() {
			var ok bool
			toId := tss.GetTestID(0)
			toS := signers[toId]
			toH, ok = toS.GetHandler().(*mtaHandler)
			Expect(ok).Should(BeTrue())

			for fromId, s := range signers {
				if toId == fromId {
					continue
				}
				fromH, ok := s.GetHandler().(*mtaHandler)
				Expect(ok).Should(BeTrue())
				Expect(toH.HandleMessage(log.Discard(), fromH.peers[toId].enck.mtaMsg)).Should(BeNil())
			}
		})

		It("failed to sum up wiG (different curve)", func() {
			toH.wiG = pt.NewBase(elliptic.Ed25519())
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(pt.ErrDifferentCurve))
		})

		It("unexpected public key", func() {
			toH.wiG = pt.NewBase(elliptic.Secp256k1())
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ErrUnexpectedPublickey))
		})

		It("failed to get ai mta GetResult", func() {
			toH.aiMta = mockMta
			mockMta.On("GetResult", mock.Anything, mock.Anything).Return(nil, unknownErr).Once()
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(unknownErr))
		})

		It("failed to get wi mta GetResult", func() {
			toH.wiMta = mockMta
			mockMta.On("GetResult", mock.Anything, mock.Anything).Return(nil, unknownErr).Once()
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(unknownErr))
		})
	})
})
