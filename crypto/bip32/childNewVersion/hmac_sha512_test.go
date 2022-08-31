// Copyright © 2021 AMIS Technologies
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

package childnewversion

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"

	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bip32 test", func() {
	DescribeTable("Compression function", func(input string) {
		inputSereilize, err := Sha512GetBlockWithPadding([]byte(input))
		Expect(err).Should(BeNil())
		got := Sha512Compression(inputSereilize, sha512InitialState())
		sha_512 := sha512.New()
		sha_512.Write([]byte(input))
		expected := sha_512.Sum(nil)
		Expect(uint64SliceToByteSlice(got)).Should(Equal(expected))
	},
		Entry("input:", "abc"),
		Entry("input:", "MarkIsGod"),
		Entry("input:", "IanIsGood"),
		Entry("input:", "EdwinIsFast"),
		Entry("input:", "UnaIsCute"),
	)

	DescribeTable("HMACSHA512", func(key []byte, input []byte) {
		hmacSha512 := NewHmacSha512(key)
		firstState, err := hmacSha512.ComputeFirstBlockHash()
		Expect(err).Should(BeNil())
		secondBlock, err := hmacSha512.GetSecondBlockHash(input)
		Expect(err).Should(BeNil())
		sencondState := Sha512Compression(secondBlock, firstState)
		got := hmacSha512.Digest(uint64SliceToByteSlice(sencondState))

		// Build-in sha512
		truehmac := hmac.New(sha512.New, key)
		truehmac.Write(input)
		expected := truehmac.Sum(nil)
		Expect(got).Should(Equal(expected))
	},
		Entry("input:", []byte("yayayayayayayayayayayayayayayaya"), []byte("abc")),
		Entry("input:", []byte("yaya"), []byte("MarkIsGod")),
		Entry("input:", []byte("yaya"), []byte("IanIsGood")),
	)

	It("NewHmacSha512()", func() {
		key, err := utils.GenRandomBytes(517)
		Expect(err).Should(BeNil())
		hmac512 := NewHmacSha512(key)
		Expect(hmac512).ShouldNot(BeNil())
	})

	It("Reset()", func() {
		hmac512 := NewHmacSha512([]byte{1})
		hmac512.Reset()
	})

	It("ComputeOutputFirstBlockHash()", func() {
		hmac512 := NewHmacSha512([]byte{1})
		_, err := hmac512.ComputeOutputFirstBlockHash()
		Expect(err).Should(BeNil())
	})

	It("GetOutputSecondBlockHash()", func() {
		hmac512 := NewHmacSha512([]byte{1})
		_, err := hmac512.GetOutputSecondBlockHash([]byte{2})
		Expect(err).Should(BeNil())
	})

	It("getSecondBlockHash()", func() {
		message, err := utils.GenRandomBytes(300)
		Expect(err).Should(BeNil())
		_, err = getSecondBlockHash(message, []byte{1})
		Expect(err).ShouldNot(BeNil())
	})
})

func uint64SliceToByteSlice(input []uint64) []byte {
	buf := new(bytes.Buffer)
	for _, in := range input {
		err := binary.Write(buf, binary.BigEndian, in)
		if err != nil {
			return nil
		}
	}
	return buf.Bytes()
}
