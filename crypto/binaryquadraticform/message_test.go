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

package binaryquadraticform

import (
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const invalidMsg = "invalid message"

var _ = Describe("Message", func() {
	var bq *BQuadraticForm
	var c *cacheExp
	BeforeEach(func() {
		var err error
		bq, err = NewBQuadraticForm(big.NewInt(33), big.NewInt(-11), big.NewInt(5))
		Expect(err).Should(BeNil())
		c = NewCacheExp(bq)
	})

	It("should be ok", func() {
		msg := bq.ToMessage()
		Expect(msg).ShouldNot(BeNil())
		got, err := msg.ToBQuadraticForm()
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(bq))
		gotC, err := msg.ToCacheExp()
		Expect(err).Should(BeNil())
		Expect(gotC).Should(Equal(c))
	})

	It("invalid a", func() {
		msg := bq.ToMessage()
		Expect(msg).ShouldNot(BeNil())
		msg.A = invalidMsg
		got, err := msg.ToBQuadraticForm()
		Expect(err).Should(Equal(ErrInvalidMessage))
		Expect(got).Should(BeNil())
		gotC, err := msg.ToCacheExp()
		Expect(err).Should(Equal(ErrInvalidMessage))
		Expect(gotC).Should(BeNil())
	})

	It("invalid b", func() {
		msg := bq.ToMessage()
		Expect(msg).ShouldNot(BeNil())
		msg.B = invalidMsg
		got, err := msg.ToBQuadraticForm()
		Expect(err).Should(Equal(ErrInvalidMessage))
		Expect(got).Should(BeNil())
		gotC, err := msg.ToCacheExp()
		Expect(err).Should(Equal(ErrInvalidMessage))
		Expect(gotC).Should(BeNil())
	})

	It("invalid c", func() {
		msg := bq.ToMessage()
		Expect(msg).ShouldNot(BeNil())
		msg.C = invalidMsg
		got, err := msg.ToBQuadraticForm()
		Expect(err).Should(Equal(ErrInvalidMessage))
		Expect(got).Should(BeNil())
		gotC, err := msg.ToCacheExp()
		Expect(err).Should(Equal(ErrInvalidMessage))
		Expect(gotC).Should(BeNil())
	})

	It("nil message", func() {
		var msg *BQForm
		got, err := msg.ToBQuadraticForm()
		Expect(err).Should(Equal(ErrInvalidMessage))
		Expect(got).Should(BeNil())
	})
})
