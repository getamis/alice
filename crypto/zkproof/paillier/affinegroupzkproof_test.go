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

var _ = Describe("Affinegroupzkproof test", func() {
	x := big.NewInt(3)
	y := big.NewInt(5)
	rhoy := big.NewInt(101)
	rho := big.NewInt(103)
	C := big.NewInt(108)
	X := pt.ScalarBaseMult(elliptic.Secp256k1(), x)
	Y := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n1), y, n1Square), new(big.Int).Exp(rhoy, n1, n1Square))
	Y.Mod(Y, n1Square)
	D := new(big.Int).Exp(C, x, n0Square)
	D.Mul(D, new(big.Int).Exp(new(big.Int).Add(big1, n0), y, n0Square))
	D.Mul(D, new(big.Int).Exp(rho, n0, n0Square))
	D.Mod(D, n0Square)

	Context("It is OK", func() {
		BeforeEach(func() {
			config = NewS256()
		})

		It("over Range, should be ok", func() {
			zkproof, err := NewPaillierAffAndGroupRangeMessage(config, ssIDInfo, x, y, rho, rhoy, n0, n1, C, D, Y, ped, X)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpLAddepsilon = big.NewInt(-10)
			zkproof, err := NewPaillierAffAndGroupRangeMessage(config, ssIDInfo, x, y, rho, rhoy, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpLpaiAddepsilon = big.NewInt(-10)
			zkproof, err := NewPaillierAffAndGroupRangeMessage(config, ssIDInfo, x, y, rho, rhoy, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			config.TwoExpL = big.NewInt(-1)
			zkproof, err := NewPaillierAffAndGroupRangeMessage(config, ssIDInfo, x, y, rho, rhoy, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			copyn := new(big.Int).Set(ped.n)
			ped.n = big.NewInt(-1)
			zkproof, err := NewPaillierAffAndGroupRangeMessage(config, ssIDInfo, x, y, rho, rhoy, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
			ped.n = copyn
		})
		It("not in range", func() {
			zkproof, err := NewPaillierAffAndGroupRangeMessage(config, ssIDInfo, x, y, rho, rhoy, big0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
		It("not in range", func() {
			zkproof, err := NewPaillierAffAndGroupRangeMessage(config, ssIDInfo, x, y, rho, rhoy, n0, big0, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("Verify tests", func() {
		var zkproof *PaillierAffAndGroupRangeMessage
		BeforeEach(func() {
			var err error
			zkproof, err = NewPaillierAffAndGroupRangeMessage(config, ssIDInfo, x, y, rho, rhoy, n0, n1, C, D, Y, ped, X)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			zkproof.S = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.S = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.T = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.T = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.A = n0Square.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.A = p0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.By = n1Square.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.By = p1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.E = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.E = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.F = pedN.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.F = pedp.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.W = n0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.W = p0.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.Wy = n1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.Wy = p1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.Z1 = new(big.Int).Lsh(big2, uint(config.LAddEpsilon)+1).String()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("not in range", func() {
			zkproof.Z2 = new(big.Int).Lsh(big2, uint(config.LpaiAddEpsilon)+1).String()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.W = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z1 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Wy = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z3 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z4 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong Point", func() {
			zkproof.Bx = nil
			err := zkproof.Verify(config, ssIDInfo, n0, n1, C, D, Y, ped, X)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
