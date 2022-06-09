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

	"github.com/getamis/alice/crypto/elliptic"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Mulzkproof test", func() {
	fieldOrder := elliptic.Secp256k1().Params().N
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
	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			zkproof, err := NewMulMessage(ssIDInfo, x, rho, rhox, n0, X, Y, C, fieldOrder)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).Should(BeNil())
		})

		It("not in range", func() {
			zkproof, err := NewMulMessage(ssIDInfo, x, rho, rhox, big1, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("Verify tests", func() {
		var zkproof *MulMessage
		BeforeEach(func() {
			var err error
			zkproof, err = NewMulMessage(ssIDInfo, x, rho, rhox, n0, X, Y, C, fieldOrder)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			zkproof.U = n0.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("not coprime", func() {
			zkproof.U = p0.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("not in range", func() {
			zkproof.V = n0.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("not coprime", func() {
			zkproof.V = p0.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("not in range", func() {
			zkproof.A = n0Square.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("not coprime", func() {
			zkproof.A = p0.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("not in range", func() {
			zkproof.B = n0Square.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("not coprime", func() {
			zkproof.B = p0.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong fieldOrder", func() {
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, big1)
			Expect(err).ShouldNot(BeNil())
		})

		It("verify failure", func() {
			zkproof.V = big1.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})

		It("verify failure", func() {
			zkproof.A = big1.Bytes()
			err := zkproof.Verify(ssIDInfo, n0, X, Y, C, fieldOrder)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
