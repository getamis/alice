// Copyright © 2020 AMIS Technologies
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

var _ = Describe("Elog test", func() {
	G := pt.NewBase(config.Curve)
	X := G.ScalarMult(big.NewInt(232579))
	h := G.ScalarMult(big.NewInt(1))
	lambda := big.NewInt(23424)
	y := big.NewInt(0)
	ssIDInfo := []byte("Mark HaHa")
	L := G.ScalarMult(lambda)
	M := G.ScalarMult(y)
	M, _ = M.Add(X.ScalarMult(lambda))
	Y := h.ScalarMult(y)
	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			zkproof, err := NewELog(config, ssIDInfo, y, lambda, L, M, X, Y, h)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(config, ssIDInfo, L, M, X, Y, h)
			Expect(err).Should(BeNil())
		})
		It("over Range, should be ok", func() {
			Xhat := pt.NewBase(elliptic.Ed25519())
			zkproof, err := NewELog(config, ssIDInfo, y, lambda, L, M, Xhat, Y, h)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("Verify tests", func() {
		var zkproof *ELogMessage
		twiceCurveN := new(big.Int).Mul(big2, G.GetCurve().Params().N).Bytes()
		BeforeEach(func() {
			var err error
			zkproof, err = NewELog(config, ssIDInfo, y, lambda, L, M, X, Y, h)
			Expect(err).Should(BeNil())
		})
		It("not in range", func() {
			zkproof.Z = twiceCurveN
			err := zkproof.Verify(config, ssIDInfo, L, M, X, Y, h)
			Expect(err).ShouldNot(BeNil())
		})
		It("not coprime", func() {
			zkproof.U = twiceCurveN
			err := zkproof.Verify(config, ssIDInfo, L, M, X, Y, h)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.Z = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, L, M, X, Y, h)
			Expect(err).ShouldNot(BeNil())
		})
		It("verify failure", func() {
			zkproof.U = big1.Bytes()
			err := zkproof.Verify(config, ssIDInfo, L, M, X, Y, h)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong Point", func() {
			zkproof.A = nil
			err := zkproof.Verify(config, ssIDInfo, L, M, X, Y, h)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong Point", func() {
			zkproof.B = nil
			err := zkproof.Verify(config, ssIDInfo, L, M, X, Y, h)
			Expect(err).ShouldNot(BeNil())
		})
		It("wrong Point", func() {
			zkproof.N = nil
			err := zkproof.Verify(config, ssIDInfo, L, M, X, Y, h)
			Expect(err).ShouldNot(BeNil())
		})
	})
})
