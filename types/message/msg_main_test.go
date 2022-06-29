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
	"context"
	"errors"
	"testing"

	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func TestMessage(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Message Suite")
}

var _ = Describe("MsgMain", func() {
	var (
		msgMain *MsgMain
		buffLen = uint32(1)

		mockListener *mocks.StateChangedListener
		mockHandler  *mocks.Handler
		mockMsg      *mocks.Message

		msgType         = types.MessageType(10)
		nextMessageType = msgType + 1
	)
	BeforeEach(func() {
		mockListener = new(mocks.StateChangedListener)
		mockHandler = new(mocks.Handler)
		mockMsg = new(mocks.Message)
		msgMain = NewMsgMain("id", buffLen, mockListener, mockHandler, msgType, nextMessageType)
	})

	AfterEach(func() {
		mockListener.AssertExpectations(GinkgoT())
		mockHandler.AssertExpectations(GinkgoT())
		mockMsg.AssertExpectations(GinkgoT())
	})

	Context("AddMessage", func() {
		It("should be ok", func() {
			mockHandler.On("MessageType").Return(msgType).Once()
			mockMsg.On("GetMessageType").Return(msgType).Twice()
			mockMsg.On("IsValid").Return(true).Once()
			err := msgMain.AddMessage(mockMsg)
			Expect(err).Should(BeNil())
		})

		It("old message", func() {
			mockHandler.On("MessageType").Return(msgType).Once()
			mockMsg.On("GetMessageType").Return(types.MessageType(9)).Once()
			err := msgMain.AddMessage(mockMsg)
			Expect(err).Should(Equal(ErrOldMessage))
		})
	})

	Context("messageLoop()", func() {
		var (
			newMockHandler *mocks.Handler

			id = "id"
		)

		BeforeEach(func() {
			mockHandler.On("MessageType").Return(msgType).Once()
			mockMsg.On("GetMessageType").Return(msgType).Twice()
			mockMsg.On("IsValid").Return(true).Once()
			err := msgMain.AddMessage(mockMsg)
			Expect(err).Should(BeNil())

			mockMsg.On("GetId").Return(id).Once()
			newMockHandler = new(mocks.Handler)
		})

		AfterEach(func() {
			newMockHandler.AssertExpectations(GinkgoT())
		})

		It("should be ok for a ready handler and there's a next handler", func() {
			ctx, cancel := context.WithCancel(context.Background())
			mockHandler.On("MessageType").Return(msgType).Once()
			mockHandler.On("IsHandled", mock.Anything, id).Return(false).Once()
			mockHandler.On("HandleMessage", mock.Anything, mockMsg).Return(nil).Once()
			mockHandler.On("GetRequiredMessageCount").Return(uint32(1)).Once()
			mockHandler.On("Finalize", mock.Anything).Return(newMockHandler, nil).Once()
			newMockHandler.On("MessageType").Return(nextMessageType).Run(func(args mock.Arguments) {
				cancel()
			}).Once()

			// The loop is closed by context cancelled
			mockListener.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
			err := msgMain.messageLoop(ctx)
			Expect(err).Should(Equal(context.Canceled))
		})

		It("should be ok for a ready handler and there's no next handler", func() {
			ctx := context.Background()
			mockHandler.On("MessageType").Return(msgType).Once()
			mockHandler.On("IsHandled", mock.Anything, id).Return(false).Once()
			mockHandler.On("HandleMessage", mock.Anything, mockMsg).Return(nil).Once()
			mockHandler.On("GetRequiredMessageCount").Return(uint32(1)).Once()
			mockHandler.On("Finalize", mock.Anything).Return(nil, nil).Once()
			mockListener.On("OnStateChanged", types.StateInit, types.StateDone).Once()
			err := msgMain.messageLoop(ctx)
			Expect(err).Should(BeNil())
		})

		Context("negative cases", func() {
			var (
				unknownErr = errors.New("unknown error")
				ctx        = context.Background()
			)
			It("failed to finalize", func() {
				mockHandler.On("MessageType").Return(msgType).Once()
				mockHandler.On("IsHandled", mock.Anything, id).Return(false).Once()
				mockHandler.On("HandleMessage", mock.Anything, mockMsg).Return(nil).Once()
				mockHandler.On("GetRequiredMessageCount").Return(uint32(1)).Once()
				mockHandler.On("Finalize", mock.Anything).Return(nil, unknownErr).Once()
				mockListener.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
				err := msgMain.messageLoop(ctx)
				Expect(err).Should(Equal(unknownErr))
			})

			It("failed to handle message", func() {
				mockHandler.On("MessageType").Return(msgType).Once()
				mockHandler.On("IsHandled", mock.Anything, id).Return(false).Once()
				mockHandler.On("HandleMessage", mock.Anything, mockMsg).Return(unknownErr).Once()
				mockListener.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
				err := msgMain.messageLoop(ctx)
				Expect(err).Should(Equal(unknownErr))
			})

			It("failed to handle message", func() {
				mockHandler.On("MessageType").Return(msgType).Once()
				mockHandler.On("IsHandled", mock.Anything, id).Return(true).Once()
				mockListener.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
				err := msgMain.messageLoop(ctx)
				Expect(err).Should(Equal(ErrDupMsg))
			})
		})
	})
})
