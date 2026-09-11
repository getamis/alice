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
	mMocks "github.com/getamis/alice/types/message/mocks"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/proto"
)

var _ = Describe("EchoMsgMain", func() {
	var (
		msgMain         *EchoMsgMain
		mockMessageMain *mocks.MessageMain
		mockPeerManager *mocks.PeerManager
		mockMsg         *mMocks.EchoMessage

		echoMsgType = types.MessageType(10)
		selfID      = "self"
		originID    = "origin"
		peerID      = "peer"
	)
	BeforeEach(func() {
		mockMsg = new(mMocks.EchoMessage)
		mockMessageMain = new(mocks.MessageMain)
		mockPeerManager = new(mocks.PeerManager)
		msgMain = NewEchoMsgMain(mockMessageMain, mockPeerManager)
		msgMain.marshalFunc = func(m proto.Message) ([]byte, error) {
			return nil, nil
		}
	})

	AfterEach(func() {
		mockMessageMain.AssertExpectations(GinkgoT())
		mockPeerManager.AssertExpectations(GinkgoT())
		mockMsg.AssertExpectations(GinkgoT())
	})

	Context("AddMessage", func() {
		It("rejects a message from a sender that is not a participant", func() {
			mockMsg.On("GetId").Return(originID)
			mockPeerManager.On("SelfID").Return(selfID)
			mockPeerManager.On("PeerIDs").Return([]string{originID, peerID})
			err := msgMain.AddMessage("stranger", mockMsg)
			Expect(err).Should(Equal(ErrInvalidRelay))
		})

		Context("not an echo-tracked message", func() {
			var nilMsg types.Message

			It("passes it straight through when sent by its own origin", func() {
				mockMsg.On("GetId").Return(selfID)
				mockMsg.On("GetEchoHashRelay").Return(nil)
				mockMsg.On("GetEchoMessage").Return(nilMsg)
				mockPeerManager.On("SelfID").Return(selfID)
				mockMessageMain.On("AddMessage", selfID, mockMsg).Return(nil)
				err := msgMain.AddMessage(selfID, mockMsg)
				Expect(err).Should(BeNil())
			})

			It("rejects it when the sender differs from its id", func() {
				mockMsg.On("GetId").Return(originID)
				mockMsg.On("GetEchoHashRelay").Return(nil)
				mockMsg.On("GetEchoMessage").Return(nilMsg)
				mockPeerManager.On("SelfID").Return(selfID)
				mockPeerManager.On("PeerIDs").Return([]string{originID, peerID})
				err := msgMain.AddMessage(peerID, mockMsg)
				Expect(err).Should(Equal(ErrInvalidRelay))
			})
		})

		Context("echo-tracked messages", func() {
			It("delivers immediately when there are no other peers to wait for", func() {
				mockMsg.On("GetMessageType").Return(echoMsgType)
				mockMsg.On("GetId").Return(selfID)
				mockMsg.On("GetEchoHashRelay").Return(nil)
				mockMsg.On("GetEchoMessage").Return(mockMsg)
				mockPeerManager.On("SelfID").Return(selfID)
				mockPeerManager.On("PeerIDs").Return([]string{})
				mockMessageMain.On("AddMessage", selfID, mockMsg).Return(nil).Once()
				err := msgMain.AddMessage(selfID, mockMsg)
				Expect(err).Should(BeNil())
			})

			It("waits until every peer has echoed before delivering", func() {
				peers := []string{originID, peerID}
				mockRelay := new(mMocks.EchoMessage)
				mockMsg.On("GetMessageType").Return(echoMsgType)
				mockMsg.On("GetId").Return(originID)
				mockMsg.On("GetEchoHashRelay").Return(nil)
				mockMsg.On("GetEchoMessage").Return(mockMsg)
				mockMsg.On("NewEchoHashRelay", mock.Anything).Return(mockRelay)
				mockRelay.On("GetId").Return(originID).Maybe()
				mockRelay.On("GetMessageType").Return(echoMsgType).Maybe()
				// The hash must match what the origin's message hashes to, so
				// this relay is treated as consistent, not conflicting.
				hash, err := msgMain.echoHash(mockMsg)
				Expect(err).Should(BeNil())
				mockRelay.On("GetEchoHashRelay").Return(hash).Maybe()
				mockPeerManager.On("SelfID").Return(selfID)
				mockPeerManager.On("PeerIDs").Return(peers)
				mockPeerManager.On("MustSend", peerID, mockRelay).Maybe()

				// Arrives directly from the authenticated origin: 2 of the 3
				// required votes (origin + self), not enough to deliver yet.
				err = msgMain.AddMessage(originID, mockMsg)
				Expect(err).Should(BeNil())
				mockMessageMain.AssertNotCalled(GinkgoT(), "AddMessage", mock.Anything, mock.Anything)

				// The last peer echoes the relayed message, completing the quorum.
				mockMessageMain.On("AddMessage", originID, mockMsg).Return(nil).Once()
				err = msgMain.AddMessage(peerID, mockRelay)
				Expect(err).Should(BeNil())
			})

			It("lets the authenticated origin correct an unconfirmed relay hash, then rejects further mismatches", func() {
				peers := []string{originID, peerID}
				mockMsg2 := new(mMocks.EchoMessage)
				mockMsg3 := new(mMocks.EchoMessage)
				for _, m := range []*mMocks.EchoMessage{mockMsg, mockMsg2, mockMsg3} {
					m.On("GetId").Return(originID)
					m.On("GetMessageType").Return(echoMsgType)
				}
				// mockMsg2 and mockMsg3 are hash-only relays carrying
				// conflicting hashes; mockMsg is the origin's full message.
				mockMsg2.On("GetEchoHashRelay").Return([]byte("B"))
				mockMsg3.On("GetEchoHashRelay").Return([]byte("C"))
				mockMsg.On("GetEchoHashRelay").Return(nil)
				mockMsg.On("GetEchoMessage").Return(mockMsg)
				mockMsg.On("NewEchoHashRelay", mock.Anything).Return(mockMsg2)
				msgMain.marshalFunc = func(m proto.Message) ([]byte, error) {
					if m == proto.Message(mockMsg) {
						return []byte("A"), nil
					}
					return nil, nil
				}
				mockPeerManager.On("SelfID").Return(selfID)
				mockPeerManager.On("PeerIDs").Return(peers)
				mockPeerManager.On("MustSend", mock.Anything, mock.Anything).Maybe()

				// An unconfirmed relay arrives first, carrying the wrong content.
				err := msgMain.AddMessage(peerID, mockMsg2)
				Expect(err).Should(BeNil())

				// The authenticated origin corrects the hash.
				err = msgMain.AddMessage(originID, mockMsg)
				Expect(err).Should(BeNil())

				// A later conflicting relay is rejected once the origin's hash is confirmed.
				err = msgMain.AddMessage(peerID, mockMsg3)
				Expect(err).Should(Equal(ErrDifferentHash))

				mockMsg2.AssertExpectations(GinkgoT())
				mockMsg3.AssertExpectations(GinkgoT())
			})
		})
	})
})
