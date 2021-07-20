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

package message

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/getamis/alice/libs/message/types"
	"github.com/getamis/alice/libs/message/types/mocks"
)

var _ = Describe("Peer", func() {
	var (
		p       *Peer
		mockMsg *mocks.Message

		msgId   = "id"
		msgType = types.MessageType(10)
	)

	BeforeEach(func() {
		mockMsg = new(mocks.Message)
		p = NewPeer(msgId)
	})

	AfterEach(func() {
		mockMsg.AssertExpectations(GinkgoT())
	})

	Context("AddMessage()", func() {
		It("should be ok", func() {
			mockMsg.On("GetId").Return(msgId).Once()
			mockMsg.On("GetMessageType").Return(msgType).Once()
			Expect(p.AddMessage(mockMsg)).Should(BeNil())
		})

		It("not your message", func() {
			mockMsg.On("GetId").Return("other-id").Once()
			Expect(p.AddMessage(mockMsg)).Should(Equal(ErrNotYours))
		})

		It("duplicate message", func() {
			mockMsg.On("GetId").Return(msgId).Once()
			mockMsg.On("GetMessageType").Return(msgType).Once()
			Expect(p.AddMessage(mockMsg)).Should(BeNil())
			mockMsg.On("GetId").Return(msgId).Once()
			mockMsg.On("GetMessageType").Return(msgType).Once()
			Expect(p.AddMessage(mockMsg)).Should(Equal(ErrDupMessage))
		})
	})

	Context("Broadcast", func() {
		var mockPeerManager *mocks.PeerManager

		BeforeEach(func() {
			mockPeerManager = new(mocks.PeerManager)
		})

		AfterEach(func() {
			mockPeerManager.AssertExpectations(GinkgoT())
		})

		It("should be ok", func() {
			peers := []string{
				"peer-1",
				"peer-2",
				"peer-3",
			}
			msg := "message"
			mockPeerManager.On("PeerIDs").Return(peers).Once()
			for _, id := range peers {
				mockPeerManager.On("MustSend", id, msg).Return(nil).Once()
			}
			Broadcast(mockPeerManager, msg)
		})
	})
})
