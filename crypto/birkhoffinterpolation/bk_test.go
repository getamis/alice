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

package birkhoffinterpolation

import (
	"math/big"

	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("BK", func() {
	Context("ToBk()", func() {
		fieldOrder := big.NewInt(100)
		It("should be ok", func() {
			x := big.NewInt(1)
			rank := uint32(10)
			bk := NewBkParameter(x, rank)
			msg := bk.ToMessage()
			gotBk, err := msg.ToBk(fieldOrder)
			Expect(bk).Should(Equal(gotBk))
			Expect(err).Should(BeNil())
		})

		It("invalid x = 0", func() {
			x := big.NewInt(0)
			rank := uint32(10)
			bk := NewBkParameter(x, rank)
			msg := bk.ToMessage()
			gotBk, err := msg.ToBk(fieldOrder)
			Expect(gotBk).Should(BeNil())
			Expect(err).Should(Equal(utils.ErrNotInRange))
		})

		It("invalid x = fieldOrder", func() {
			x := fieldOrder
			rank := uint32(10)
			bk := NewBkParameter(x, rank)
			msg := bk.ToMessage()
			gotBk, err := msg.ToBk(fieldOrder)
			Expect(gotBk).Should(BeNil())
			Expect(err).Should(Equal(utils.ErrNotInRange))
		})
	})
})
