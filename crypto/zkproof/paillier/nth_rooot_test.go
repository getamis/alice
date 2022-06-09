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

var _ = Describe("Nth Root test", func() {
	Context("It is OK", func() {
		rho := big.NewInt(103)
		NPower := new(big.Int).Exp(rho, n0, n0Square)
		NPower.Mod(NPower, n0Square)
		It("over Range, should be ok", func() {
			zkproof, err := NewNthRoot(config, ssIDInfo, rho, NPower, n0)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(config, ssIDInfo, NPower, n0)
			Expect(err).Should(BeNil())
		})

		It("not in range", func() {
			zkproof, err := NewNthRoot(config, ssIDInfo, rho, NPower, big.NewInt(-1))
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("verify test", func() {
		var zkproof *NthRootMessage
		rho := big.NewInt(103)
		NPower := new(big.Int).Exp(rho, n0, n0Square)
		BeforeEach(func() {
			var err error
			config.Curve.Params().N = S256N
			zkproof, err = NewNthRoot(config, ssIDInfo, rho, NPower, n0)
			Expect(err).Should(BeNil())
		})

		It("not in range", func() {
			zkproof.A = new(big.Int).Set(n0Square).Bytes()
			err := zkproof.Verify(config, ssIDInfo, NPower, n0)
			Expect(err).ShouldNot(BeNil())
		})

		It("not coprime", func() {
			zkproof.A = new(big.Int).Set(p0).Bytes()
			err := zkproof.Verify(config, ssIDInfo, NPower, n0)
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong fieldOrder", func() {
			config.Curve.Params().N = big1
			err := zkproof.Verify(config, ssIDInfo, NPower, n0)
			Expect(err).ShouldNot(BeNil())
		})

		It("not in range", func() {
			zkproof.Z1 = new(big.Int).Set(n0).Bytes()
			err := zkproof.Verify(config, ssIDInfo, NPower, n0)
			Expect(err).ShouldNot(BeNil())
		})

		It("verify failure", func() {
			zkproof.A = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, NPower, n0)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
