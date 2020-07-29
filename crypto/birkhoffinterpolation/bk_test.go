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
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("BK", func() {
	It("ToBk()", func() {
		x := big.NewInt(1)
		rank := uint32(10)
		bk := NewBkParameter(x, rank)
		msg := bk.ToMessage()
		gotBk := msg.ToBk()
		Expect(bk).Should(Equal(gotBk))
	})

	It("ToBk2()", func() {
		key := []byte("14725836qazwsxed")

		block, _ := aes.NewCipher(key)
		//iv := []byte("asdada")
		iv, _ := utils.GenRandomBytes(block.BlockSize())
		blockMode := cipher.NewCTR(block, iv)
		text := []byte("257111")
		fmt.Println(text)
		message := make([]byte, len(text))
		blockMode.XORKeyStream(message, text)
		fmt.Println(message)
	})
})
