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
	x := big.NewInt(3)
	rho := big.NewInt(103)
	C := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n0), x, n0Square), new(big.Int).Exp(rho, n0, n0Square))
	C.Mod(C, n0Square)
	X := pt.ScalarBaseMult(config.Curve, x)
	G := pt.NewBase(config.Curve)
	Context("It is OK", func() {
		BeforeEach(func() {
			config = NewS256()
		})
		It("over Range, should be ok", func() {
			zkproof, err := NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, n0, ped, X, G)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpLAddepsilon = big.NewInt(-1)
			zkproof, err := NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpL = big.NewInt(-1)
			zkproof, err := NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpLAddepsilon = big.NewInt(-1)
			zkproof, err := NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			zkproof, err := NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, big.NewInt(0), ped, X, G)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("Verify tests", func() {
		var zkproof *LogStarMessage
		BeforeEach(func() {
			var err error
			zkproof, err = NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, n0, ped, X, G)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			zkproof.S = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.S = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.D = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.D = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.A = n0Square.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.A = p0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.Z2 = n0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.Z2 = p0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong point", func() {
			zkproof.Y = nil
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong fieldOrder", func() {
			config.Curve.Params().N = big1
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
			config.Curve.Params().N = S256N
		})
		It("not in range", func() {
			zkproof.Z1 = new(big.Int).Lsh(big4, uint(config.LAddEpsilon)).String()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z3 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z1 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z2 = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, C, n0, ped, X, G)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
