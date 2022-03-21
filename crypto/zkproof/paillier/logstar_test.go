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

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Logstar test", func() {
	config := NewS256()
	p0, _ := new(big.Int).SetString("104975615121222854384410219330480259027041155688835759631647658735069527864919393410352284436544267374160206678331198777612866309766581999589789442827625308608614590850591998897357449886061863686453412019330757447743487422636807387508460941025550338019105820406950462187693188000168607236389735877001362796259", 10)
	q0, _ := new(big.Int).SetString("102755306389915984635356782597494195047102560555160692696207839728487252530690043689166546890155633162017964085393843240989395317546293846694693801865924045225783240995686020308553449158438908412088178393717793204697268707791329981413862246773904710409946848630083569401668855899757371993960961231481357354607", 10)
	n0 := new(big.Int).Mul(p0, q0)
	n0Square := new(big.Int).Exp(n0, big2, nil)
	ssIDInfo := []byte("Mark HaHa")
	pedp, _ := new(big.Int).SetString("172321190316317406041983369591732729491350806968006943303929709788136215251460267633420533682689046013587054841341976463526601587002102302546652907431187846060997247514915888514444763709031278321293105031395914163838109362462240334430371455027991864100292721059079328191363601847674802011142994248364894749407", 10)
	pedq, _ := new(big.Int).SetString("133775161118873760646458598449594229708046435932335011961444226591456542241216521727451860331718305184791260558214309464515443345834395848652314690639803964821534655704923535199917670451716761498957904445631495169583566095296670783502280310288116580525460451464561679063318393570545894032154226243881186182059", 10)
	pedN := new(big.Int).Mul(pedp, pedq)
	pedt := big.NewInt(9)
	peds := big.NewInt(729)

	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			x := big.NewInt(3)
			rho := big.NewInt(103)
			C := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n0), x, n0Square), new(big.Int).Exp(rho, n0, n0Square))
			C.Mod(C, n0Square)
			X := pt.ScalarBaseMult(config.Curve, x)
			G := pt.NewBase(config.Curve)

			zkproof, err := NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, n0, pedN, peds, pedt, X, G)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(config, ssIDInfo, C, n0, pedN, peds, pedt, X, G)
			Expect(err).Should(BeNil())
		})
	})
})
