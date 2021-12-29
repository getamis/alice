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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("P256", func() {
	Context("Negative Point", func() {
		FIt("It is OK", func() {
			P256 := NewP256()
			negX, negY := P256.Neg(P256.Params().Gx, P256.Params().Gy)
			scalX, scalY := P256.ScalarBaseMult(new(big.Int).Sub(P256.Params().N, big.NewInt(1)).Bytes())
			fmt.Println( P256.Add(P256.Params().Gx, P256.Params().Gy, scalX, scalY ) )

			Expect(negX.Cmp(scalX) == 0).Should(BeTrue())
			Expect(negY.Cmp(scalY) == 0).Should(BeTrue())
		})
	})
})
