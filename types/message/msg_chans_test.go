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

	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MessageChan", func() {
	var (
		msgChans *MsgChans
		mockMsg  *mocks.Message

		msgType = types.MessageType(10)
		buffLen = uint32(1)
		ctx     = context.Background()
	)
	BeforeEach(func() {
		msgChans = NewMsgChans(buffLen, msgType)
		mockMsg = new(mocks.Message)
	})

	AfterEach(func() {
		mockMsg.AssertExpectations(GinkgoT())
	})

	It("should be ok", func() {
		mockMsg.On("GetMessageType").Return(msgType).Once()
		mockMsg.On("IsValid").Return(true).Once()
		err := msgChans.Push(mockMsg)
		Expect(err).Should(BeNil())
		got, err := msgChans.Pop(ctx, msgType)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(mockMsg))
	})

	It("cancelled context", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := msgChans.Pop(ctx, msgType)
		Expect(err).Should(Equal(context.Canceled))
		Expect(got).Should(BeNil())
	})

	It("pop undefined message", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := msgChans.Pop(ctx, types.MessageType(11))
		Expect(err).Should(Equal(ErrUndefinedMessage))
		Expect(got).Should(BeNil())
	})

	It("push full channel", func() {
		mockMsg.On("GetMessageType").Return(msgType).Once()
		mockMsg.On("IsValid").Return(true).Once()
		err := msgChans.Push(mockMsg)
		Expect(err).Should(BeNil())
		mockMsg.On("GetMessageType").Return(msgType).Once()
		mockMsg.On("IsValid").Return(true).Once()
		err = msgChans.Push(mockMsg)
		Expect(err).Should(Equal(ErrFullChannel))
	})

	It("push invalid message", func() {
		mockMsg.On("GetMessageType").Return(msgType).Once()
		mockMsg.On("IsValid").Return(false).Once()
		err := msgChans.Push(mockMsg)
		Expect(err).Should(Equal(ErrInvalidMessage))
	})

	It("push undefined message", func() {
		mockMsg.On("GetMessageType").Return(types.MessageType(11)).Once()
		err := msgChans.Push(mockMsg)
		Expect(err).Should(Equal(ErrUndefinedMessage))
	})
})
