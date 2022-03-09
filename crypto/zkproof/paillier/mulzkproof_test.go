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

	"github.com/btcsuite/btcd/btcec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Mulzkproof test", func() {
	p0, _ := new(big.Int).SetString("104975615121222854384410219330480259027041155688835759631647658735069527864919393410352284436544267374160206678331198777612866309766581999589789442827625308608614590850591998897357449886061863686453412019330757447743487422636807387508460941025550338019105820406950462187693188000168607236389735877001362796259", 10)
	q0, _ := new(big.Int).SetString("102755306389915984635356782597494195047102560555160692696207839728487252530690043689166546890155633162017964085393843240989395317546293846694693801865924045225783240995686020308553449158438908412088178393717793204697268707791329981413862246773904710409946848630083569401668855899757371993960961231481357354607", 10)
	n0 := new(big.Int).Mul(p0, q0)
	n0Square := new(big.Int).Exp(n0, big2, nil)
	ssIDInfo := []byte("Mark HaHa")

	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			fieldOrder := btcec.S256().N
			x := big.NewInt(3)
			rho := big.NewInt(103)
			rhox := big.NewInt(203)
			X := new(big.Int).Add(big1, n0)
			X.Exp(X, x, n0Square)
			X.Mul(X, new(big.Int).Exp(rhox, n0, n0Square))
			X.Mod(X, n0Square)
			Y := big.NewInt(234256)
			C := new(big.Int).Exp(Y, x, n0Square)
			C.Mul(C, new(big.Int).Exp(rho, n0, n0Square))
			C.Mod(C, n0Square)

			zkproof, err := NewMulMessage(ssIDInfo, x, rho, rhox, n0, X, Y, C, fieldOrder)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).Should(BeNil())
		})
	})
})
