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
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("EchoMsgMain", func() {
	var (
		msgMain         types.MessageMain
		mockMessageMain *mocks.MessageMain
		mockPeerManager *mocks.PeerManager
		mockMsg         *mocks.Message

		echoMsgType    = types.MessageType(10)
		nonEchoMsgType = types.MessageType(11)
		hash           = []byte("hash")
	)
	BeforeEach(func() {
		mockMsg = new(mocks.Message)
		mockMessageMain = new(mocks.MessageMain)
		mockPeerManager = new(mocks.PeerManager)
		msgMain = NewEchoMsgMain(mockMessageMain, mockPeerManager, echoMsgType)
	})

	AfterEach(func() {
		mockMessageMain.AssertExpectations(GinkgoT())
		mockPeerManager.AssertExpectations(GinkgoT())
		mockMsg.AssertExpectations(GinkgoT())
	})

	Context("AddMessage", func() {
		It("should be ok for not echo message", func() {
			mockMsg.On("GetMessageType").Return(nonEchoMsgType).Once()
			mockMessageMain.On("AddMessage", mockMsg).Return(nil).Once()
			err := msgMain.AddMessage(mockMsg)
			Expect(err).Should(BeNil())
		})

		Context("echo messages", func() {
			msgId := "id"
			otherPeerId := "other-id"
			It("should be ok for the first message", func() {
				mockMsg.On("GetMessageType").Return(echoMsgType).Once()
				mockMsg.On("Hash").Return(hash, nil).Once()
				mockMsg.On("GetId").Return(msgId).Once()
				mockPeerManager.On("PeerIDs").Return([]string{msgId, otherPeerId}).Once()
				mockPeerManager.On("MustSend", otherPeerId, mockMsg).Maybe()
				mockPeerManager.On("NumPeers").Return(uint32(1)).Once()
				mockMessageMain.On("AddMessage", mockMsg).Return(nil).Once()
				err := msgMain.AddMessage(mockMsg)
				Expect(err).Should(BeNil())
			})

			It("should be ok for the first message but not handle", func() {
				mockMsg.On("GetMessageType").Return(echoMsgType).Once()
				mockMsg.On("Hash").Return(hash, nil).Once()
				mockMsg.On("GetId").Return(msgId).Once()
				mockPeerManager.On("PeerIDs").Return([]string{msgId, otherPeerId}).Once()
				mockPeerManager.On("MustSend", otherPeerId, mockMsg).Maybe()
				mockPeerManager.On("NumPeers").Return(uint32(2)).Once()
				err := msgMain.AddMessage(mockMsg)
				Expect(err).Should(BeNil())
			})

			It("different hash", func() {
				mockMsg.On("GetMessageType").Return(echoMsgType).Once()
				mockMsg.On("Hash").Return(hash, nil).Once()
				mockMsg.On("GetId").Return(msgId).Once()
				mockPeerManager.On("PeerIDs").Return([]string{msgId, otherPeerId}).Once()
				mockPeerManager.On("MustSend", otherPeerId, mockMsg).Maybe()
				mockPeerManager.On("NumPeers").Return(uint32(2)).Once()
				err := msgMain.AddMessage(mockMsg)
				Expect(err).Should(BeNil())

				mockMsg.On("GetMessageType").Return(echoMsgType).Once()
				mockMsg.On("Hash").Return([]byte("wrong hash"), nil).Once()
				mockMsg.On("GetId").Return(msgId).Once()
				err = msgMain.AddMessage(mockMsg)
				Expect(err).Should(Equal(ErrDifferentHash))
			})
		})
	})
})
