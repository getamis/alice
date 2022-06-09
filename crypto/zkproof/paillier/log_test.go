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
	"github.com/getamis/alice/crypto/elliptic"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Log test", func() {
	ssid := []byte("Una HaHa")
	G := pt.NewBase(elliptic.Secp256k1())
	h := G.ScalarMult(big.NewInt(28397529))
	x := big.NewInt(309098)
	X := pt.ScalarBaseMult(elliptic.Secp256k1(), x)
	Y := h.ScalarMult(x)

	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			zkproof, err := NewLog(ssid, x, G, h, X, Y)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(ssid, G, h, X, Y)
			Expect(err).Should(BeNil())
		})
	})

	Context("Verify tests", func() {
		var zkproof *LogMessage
		BeforeEach(func() {
			var err error
			zkproof, err = NewLog(ssid, x, G, h, X, Y)
			Expect(err).Should(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z = big1.Bytes()
			err := zkproof.Verify(ssid, G, h, X, Y)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			tempPoint := pt.NewBase(elliptic.Ed25519())
			ptMsg, err := tempPoint.ToEcPointMessage()
			Expect(err).Should(BeNil())
			zkproof.A = ptMsg
			err = zkproof.Verify(ssid, G, h, X, Y)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			tempPoint := pt.NewBase(elliptic.Ed25519())
			ptMsg, err := tempPoint.ToEcPointMessage()
			Expect(err).Should(BeNil())
			zkproof.B = ptMsg
			err = zkproof.Verify(ssid, G, h, X, Y)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong point", func() {
			zkproof.A = nil
			err := zkproof.Verify(ssid, G, h, X, Y)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong point", func() {
			zkproof.B = nil
			err := zkproof.Verify(ssid, G, h, X, Y)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
