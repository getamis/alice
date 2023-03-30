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
	"math/big"

	. "github.com/onsi/ginkgo"
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
})
