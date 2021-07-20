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
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/oprf"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/libs/message/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("password server handler, negative cases", func() {
	var (
		mockPeerManager *mocks.PeerManager

		peerID = "peer_id"
		ph     *passwordServerHandler
	)
	BeforeEach(func() {
		mockPeerManager = new(mocks.PeerManager)

		mockPeerManager.On("NumPeers").Return(uint32(1)).Once()
		mockPeerManager.On("PeerIDs").Return([]string{peerID}).Once()
		var err error
		ph, err = newPasswordPeerServerHandler(mockPeerManager)
		Expect(err).Should(BeNil())
	})
	AfterEach(func() {
		mockPeerManager.AssertExpectations(GinkgoT())
	})

	It("peer numbers is not 1", func() {
		mockPeerManager.On("NumPeers").Return(uint32(2)).Once()
		got, err := newPasswordPeerServerHandler(mockPeerManager)
		Expect(err).Should(Equal(ErrInvalidPeerNum))
		Expect(got).Should(BeNil())
	})

	Context("IsHandled", func() {
		var (
			peerId = "peer-id"
		)
		It("peer not found", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			ph.peers[peerId] = &oprfServerData{
				request: &BodyOPRFRequest{},
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

		It("invalid user x (zero)", func() {
			msg := &Message{
				Type: Type_OPRFRequest,
				Id:   peerID,
				Body: &Message_OprfRequest{
					OprfRequest: &BodyOPRFRequest{},
				},
			}
			Expect(ph.HandleMessage(log.Discard(), msg)).Should(Equal(ErrInvalidUserX))
		})

		It("invalid user x (field order)", func() {
			msg := &Message{
				Type: Type_OPRFRequest,
				Id:   peerID,
				Body: &Message_OprfRequest{
					OprfRequest: &BodyOPRFRequest{
						X: ph.fieldOrder.Bytes(),
					},
				},
			}
			Expect(ph.HandleMessage(log.Discard(), msg)).Should(Equal(ErrInvalidUserX))
		})

		It("invalid request", func() {
			msg := &Message{
				Type: Type_OPRFRequest,
				Id:   peerID,
				Body: &Message_OprfRequest{
					OprfRequest: &BodyOPRFRequest{
						X:       []byte("invalid request"),
						Request: &oprf.OprfRequestMessage{},
					},
				},
			}
			Expect(ph.HandleMessage(log.Discard(), msg)).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
		})
	})

	Context("Finalize", func() {
		It("large threshold", func() {
			ph.userX = big.NewInt(100)
			ph.threshold = 3
			mockPeerManager.On("NumPeers").Return(uint32(1)).Once()
			got, err := ph.Finalize(log.Discard())
			Expect(err).Should(Equal(utils.ErrLargeThreshold))
			Expect(got).Should(BeNil())
		})
	})
})
