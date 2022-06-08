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

var _ = Describe("Encrange elcommitmentzkproof test", func() {
	G := pt.NewBase(config.Curve)
	a := big.NewInt(3)
	b := big.NewInt(5)
	x := big.NewInt(12)
	A := G.ScalarMult(a)
	B := G.ScalarMult(b)
	X := G.ScalarMult(new(big.Int).Add(new(big.Int).Mul(a, b), x))
	rho := big.NewInt(5)
	ciphertext := new(big.Int).Exp(new(big.Int).Add(big1, n0), x, n0Square)
	ciphertext.Mul(ciphertext, new(big.Int).Exp(rho, n0, n0Square))
	ciphertext.Mod(ciphertext, n0Square)
	Context("It is OK", func() {
		BeforeEach(func() {
			config = NewS256()
		})
		It("over Range, should be ok", func() {
			zkproof, err := NewEncryptRangeWithELMessage(config, ssIDInfo, x, rho, a, b, ciphertext, n0, A, B, X, ped)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpLAddepsilon = big.NewInt(-1)
			zkproof, err := NewEncryptRangeWithELMessage(config, ssIDInfo, x, rho, a, b, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpL = big.NewInt(-1)
			zkproof, err := NewEncryptRangeWithELMessage(config, ssIDInfo, x, rho, a, b, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			zkproof, err := NewEncryptRangeWithELMessage(config, ssIDInfo, x, rho, a, b, ciphertext, big.NewInt(-1), A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("Verify tests", func() {
		var zkproof *EncElgMessage
		BeforeEach(func() {
			var err error
			zkproof, err = NewEncryptRangeWithELMessage(config, ssIDInfo, x, rho, a, b, ciphertext, n0, A, B, X, ped)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			zkproof.S = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.S = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.T = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.T = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.D = n0Square.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.D = p0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.Z2 = n0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.Z2 = p0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z1 = new(big.Int).Lsh(big2, uint(config.LAddEpsilon)+1).String()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z1 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.W = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.W = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z3 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z2 = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong point", func() {
			zkproof.Y = nil
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong point", func() {
			zkproof.Z = nil
			err := zkproof.Verify(config, ssIDInfo, ciphertext, n0, A, B, X, ped)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
