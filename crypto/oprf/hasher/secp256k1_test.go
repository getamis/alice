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
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
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
		Entry("aaaaaaaaaaaaaaaa", []byte("aaaaaaaaaaaaaaaa")),
	)

	// The test vectors are given in https://tools.ietf.org/pdf/draft-irtf-cfrg-hash-to-curve-07.pdf
	// G.8.4. secp256k1_XMD:SHA-256_SVDW_NU_
	DescribeTable("Hash()", func(ustring, xstring, ystring string) {
		u, _ := new(big.Int).SetString(ustring, 10)
		x, _ := new(big.Int).SetString(xstring, 10)
		y, _ := new(big.Int).SetString(ystring, 10)
		point, err := hash(u, btcec.S256())

		Expect(err).Should(BeNil())
		Expect(point.GetX().Cmp(x) == 0).Should(BeTrue())
		Expect(point.GetY().Cmp(y) == 0).Should(BeTrue())
	},
		Entry("u: , x: , y:", "25081991753825674135176924025955786789579442667872762779462603343464581283759",
			"88149279462056170809389507165044720258895800224896757910527083311788859112272",
			"20318835085848713258977462600607756208623267069019692153795129140542981409017"),

		Entry("u: , x: , y:", "45297596815420124565120612464338617043920939125657531779504482305260859313931",
			"96771400963345448361070599727890032489085520920950140419108973807516139195271",
			"86979627287338515200531276578791753553505160316017187189059144303434079107517"),

		Entry("u: , x: , y:", "85705899185276584638929823137392809252703605645003270557154321590455337778611",
			"76393154936902116780453708929823945058865318074717149714595472080355028981662",
			"101484483478563308209320159308323674939056318254354169943246794689259615025231"),

		Entry("u: , x: , y:", "46751134167885241829255579533093049648058216658956642165927209636617624953010",
			"33355323280154083592035811988822528773972296434499951222838774711410503070023",
			"108755712147393702963759806273220234758530213786111496358095651421554945906736"),
	)

	Context("Special case", func() {
		It("u=0", func() {
			_, err := hash(big.NewInt(0), btcec.S256())
			Expect(err).Should(BeNil())
		})
	})
})

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "harsher Test")
}
