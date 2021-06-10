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
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	homoMocks "github.com/getamis/alice/crypto/homo/mocks"
	"github.com/getamis/alice/crypto/oprf"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("password user handler, negative cases", func() {
	var (
		ph *passwordUserHandler

		peerId   = "peer-id"
		password = []byte("password")
	)
	BeforeEach(func() {
		ph = &passwordUserHandler{
			peers: make(map[string]*oprfUserData),
		}
	})
	Context("newPasswordUserHandler", func() {
		var (
			mockPeerManager *mocks.PeerManager
			mockHomo        *homoMocks.Crypto
			bks             map[string]*birkhoffinterpolation.BkParameter

			curve     = btcec.S256()
			gScale    = big.NewInt(5987)
			expPublic = ecpointgrouplaw.ScalarBaseMult(curve, gScale)
		)
		BeforeEach(func() {
			mockPeerManager = new(mocks.PeerManager)
			mockHomo = new(homoMocks.Crypto)

			bks = map[string]*birkhoffinterpolation.BkParameter{
				"1": birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0),
				"2": birkhoffinterpolation.NewBkParameter(big.NewInt(10), 0),
			}
		})
		AfterEach(func() {
			mockPeerManager.AssertExpectations(GinkgoT())
			mockHomo.AssertExpectations(GinkgoT())
		})

		It("invalid peer number", func() {
			mockPeerManager.On("NumPeers").Return(uint32(3)).Once()
			got, err := newPasswordUserHandler(expPublic, mockPeerManager, mockHomo, password, bks, nil)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ErrInvalidPeerNum))
		})

		It("invalid curve", func() {
			mockPeerManager.On("NumPeers").Return(uint32(tss.PasswordN - 1)).Once()
			expPublic := ecpointgrouplaw.ScalarBaseMult(elliptic.P256(), gScale)
			got, err := newPasswordUserHandler(expPublic, mockPeerManager, mockHomo, password, bks, nil)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ErrNotS256Curve))
		})

		It("invalid rank", func() {
			bks["1"] = birkhoffinterpolation.NewBkParameter(big.NewInt(1), 1)
			mockPeerManager.On("NumPeers").Return(uint32(tss.PasswordN - 1)).Once()
			got, err := newPasswordUserHandler(expPublic, mockPeerManager, mockHomo, password, bks, nil)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ErrInvalidBk))
		})
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			ph.peers[peerId] = &oprfUserData{
				response: &oprf.OprfResponseMessage{},
			}
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})
	})

	Context("HandleMessage", func() {
		BeforeEach(func() {
			ph.peers[peerId] = &oprfUserData{}
		})

		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			Expect(ph.HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
		})

		It("invalid oprf response", func() {
			msg := &Message{
				Id: peerId,
				Body: &Message_OprfResponse{
					OprfResponse: &oprf.OprfResponseMessage{},
				},
			}
			Expect(ph.HandleMessage(log.Discard(), msg)).Should(Equal(pt.ErrInvalidPoint))
		})
	})
})
