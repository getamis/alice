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
package elliptic

import (
	"fmt"
	"math/big"

	"github.com/getamis/ristretto255"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ed25519", func() {
	Context("Negative Point", func() {
		FIt("It is OK", func() {
			ed25519 := NewEd25519()
			negX, negY := ed25519.Neg(ed25519.Params().Gx, ed25519.Params().Gy)
			scalX, scalY := ed25519.ScalarBaseMult(new(big.Int).Sub(ed25519.Params().N, big.NewInt(1)).Bytes())
			Expect(negX.Cmp(scalX) == 0).Should(BeTrue())
			Expect(negY.Cmp(scalY) == 0).Should(BeTrue())

			fmt.Println(ed25519.ScalarBaseMult(big.NewInt(10).Bytes()))
			scalar := ristretto255.NewScalar()
			zero := make([]byte, 32-len(big.NewInt(10).Bytes()))
			xByte := append(zero, big.NewInt(1).Bytes()...)
			scalar.Decode(xByte)
			result := ristretto255.NewElement()
			result.ScalarBaseMult(scalar)
			fmt.Println(result)

		})
	})
})
