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

var _ = Describe("Deczkproof test", func() {
	x := big.NewInt(3)
	y := new(big.Int).Set(x)
	rho := big.NewInt(5)
	C := new(big.Int).Exp(new(big.Int).Add(big1, n0), y, n0Square)
	C.Mul(C, new(big.Int).Exp(rho, n0, n0Square))
	C.Mod(C, n0Square)

	Context("It is OK", func() {
		BeforeEach(func() {
			config = NewS256()
		})
		It("over Range, should be ok", func() {
			zkproof, err := NewDecryMessage(config, ssIDInfo, y, rho, n0, C, x, ped)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpL = big.NewInt(-1)
			zkproof, err := NewDecryMessage(config, ssIDInfo, y, rho, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpLAddepsilon = big.NewInt(-1)
			zkproof, err := NewDecryMessage(config, ssIDInfo, y, rho, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			copyn := new(big.Int).Set(ped.n)
			ped.n = big.NewInt(-1)
			zkproof, err := NewDecryMessage(config, ssIDInfo, y, rho, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
			ped.n = copyn
		})
		It("not in range", func() {
			zkproof, err := NewDecryMessage(config, ssIDInfo, y, rho, big0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("Verify tests", func() {
		var zkproof *DecryMessage
		BeforeEach(func() {
			var err error
			zkproof, err = NewDecryMessage(config, ssIDInfo, y, rho, n0, C, x, ped)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			zkproof.S = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.S = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.T = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.T = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.W = n0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.W = p0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.A = n0Square.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.A = p0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.Gamma = new(big.Int).Add(big1, config.Curve.Params().N).Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong fieldOrder", func() {
			config.Curve.Params().N = big1
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
			config.Curve.Params().N = S256N
		})
		It("verify failure", func() {
			zkproof.W = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z1 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z2 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, n0, C, x, ped)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
