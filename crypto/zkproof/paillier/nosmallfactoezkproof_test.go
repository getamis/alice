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

var _ = Describe("Nosmallfactoezkproof test", func() {
	rho := []byte("Ian HaHa")
	BeforeEach(func() {
		config = NewS256()
		config.Curve.Params().N = S256N
	})

	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			zkproof, err := NewNoSmallFactorMessage(config, ssIDInfo, rho, p0, q0, n0, ped)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(config, ssIDInfo, rho, n0, ped)
			Expect(err).Should(BeNil())
		})

		It("not in range", func() {
			copyn := new(big.Int).Set(ped.n)
			ped.n = big.NewInt(-1)
			zkproof, err := NewNoSmallFactorMessage(config, ssIDInfo, rho, p0, q0, n0, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
			ped.n = copyn
		})

		It("not in range", func() {
			config.TwoExpLAddepsilon = big.NewInt(-1)
			zkproof, err := NewNoSmallFactorMessage(config, ssIDInfo, rho, p0, q0, n0, ped)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("It is OK", func() {
		var zkproof *NoSmallFactorMessage
		BeforeEach(func() {
			config = NewS256()
			config.Curve.Params().N = S256N
			var err error
			zkproof, err = NewNoSmallFactorMessage(config, ssIDInfo, rho, p0, q0, n0, ped)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			zkproof.Z1 = new(big.Int).Lsh(big4, uint(config.LAddEpsilon)).String()
			err := zkproof.Verify(config, ssIDInfo, rho, n0, ped)
			Expect(err).ShouldNot(BeNil())
		})

		It("not in range", func() {
			zkproof.Z2 = new(big.Int).Lsh(n0, uint(config.LpaiAddEpsilon)).String()
			err := zkproof.Verify(config, ssIDInfo, rho, n0, ped)
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong fieldOrder", func() {
			config.Curve.Params().N = big1
			err := zkproof.Verify(config, ssIDInfo, rho, n0, ped)
			Expect(err).ShouldNot(BeNil())
		})

		It("not in range", func() {
			zkproof.A = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, rho, n0, ped)
			Expect(err).ShouldNot(BeNil())
		})

		It("not in range", func() {
			zkproof.Z2 = big1.String()
			err := zkproof.Verify(config, ssIDInfo, rho, n0, ped)
			Expect(err).ShouldNot(BeNil())
		})

		It("not in range", func() {
			zkproof.Vletter = big1.String()
			err := zkproof.Verify(config, ssIDInfo, rho, n0, ped)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
