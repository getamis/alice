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
package hasher

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("harsher test", func() {
	DescribeTable("Hash()", func(pw []byte) {
		harsher := NewSECP256k1()
		point, err := harsher.Hash(pw)
		Expect(err).Should(BeNil())
		Expect(point.GetCurve().IsOnCurve(point.GetX(), point.GetY())).Should(BeTrue())
	},
		Entry("asdfsdfgdfs", []byte("asdfsdfgdfs")),
		Entry("0", []byte("0")),
		Entry("8077919", []byte("8077919")),
		Entry("807adjf;ajdfajdf;ajfowieurqorupqurp7919", []byte("807adjf;ajdfajdf;ajfowieurqorupqurp7919")),
		Entry("aaaaaaaaaaaaaaaa", []byte("aaaaaaaaaaaaaaaa")),
	)
})

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "harsher Test")
}
