// Copyright © 2022 AMIS Technologies
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

package paillier

import (
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Blummodzkproof test", func() {
	p, _ := new(big.Int).SetString("724334377473689364544838428087481034584099153487855340008424871105046166518428970750574404355303850918007125792350135220204204914450213831218820360920136994359584963169366146339629206326690417884172903949709795973492622857252471234238734443420121520959794039877095360362260419273921676996295515593562694725039318971623", 10)
	q, _ := new(big.Int).SetString("102755306389915984635356782597494195047102560555160692696207839728487252530690043689166546890155633162017964085393843240989395317546293846694693801865924045225783240995686020308553449158438908412088178393717793204697268707791329981413862246773904710409946848630083569401668855899757371993960961231481357354607", 10)
	n := new(big.Int).Mul(p, q)
	ssIDInfo := []byte("Mark HaHa")

	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			zkproof, err := NewPaillierBlumMessage(ssIDInfo, p, q, n, MINIMALCHALLENGE)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(ssIDInfo, n)
			Expect(err).Should(BeNil())
		})
	})

})
