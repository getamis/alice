// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package elliptic

import (
	"encoding/hex"
	"math/big"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("secp256k1", func() {
	var _ Curve = Secp256k1()
	Context("Negative Point", func() {
		It("It is OK", func() {
			secp256k1 := Secp256k1()
			negX, negY := secp256k1.Neg(secp256k1.Params().Gx, secp256k1.Params().Gy)
			scalX, scalY := secp256k1.ScalarBaseMult(new(big.Int).Sub(secp256k1.Params().N, big.NewInt(1)).Bytes())
			Expect(negX.Cmp(scalX) == 0).Should(BeTrue())
			Expect(negY.Cmp(scalY) == 0).Should(BeTrue())
		})
	})

	DescribeTable("Compressed PubKey", func(secrethex string, expected string) {
		secret, _ := new(big.Int).SetString(secrethex, 16)
		Expect(hex.EncodeToString(Secp256k1().CompressedPublicKey(secret, "test")) == expected).Should(BeTrue())
	},
		Entry("case1:", "f91d8f3a49805fff9289769247e984b355939679f3080156fe295229e00f25af", "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"),
		Entry("case2:", "ac609e0cc9681f8cb63e968be20e0f19721751561944f5b4e52d54d5f27ec57b", "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"),
	)
})

func TestEllipticcurve(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ellipticcurve Suite")
}
