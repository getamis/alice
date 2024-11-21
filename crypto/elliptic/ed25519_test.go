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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("ed25519", func() {
	var _ Curve = Ed25519()
	Context("Negative Point", func() {
		It("It is OK", func() {
			ed25519 := Ed25519()
			negX, negY := ed25519.Neg(ed25519.Params().Gx, ed25519.Params().Gy)
			scalX, scalY := ed25519.ScalarBaseMult(new(big.Int).Sub(ed25519.Params().N, big.NewInt(1)).Bytes())
			Expect(negX.Cmp(scalX) == 0).Should(BeTrue())
			Expect(negY.Cmp(scalY) == 0).Should(BeTrue())
		})
	})
	// Test vectors : https://asecuritysite.com/ecc/eddsa4
	DescribeTable("Compressed PubKey", func(secrethex string, expected string) {
		secret, _ := new(big.Int).SetString(secrethex, 16)
		Expect(hex.EncodeToString(Ed25519().CompressedPublicKey(secret, "test")) == expected).Should(BeTrue())
	},
		Entry("case1:", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
		Entry("case2:", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
		Entry("case3:", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
	)
})
