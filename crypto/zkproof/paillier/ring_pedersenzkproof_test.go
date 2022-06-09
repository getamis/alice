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
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPaillierZkProof(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Paillier Zk proof Suite")
}

var _ = Describe("Ring pedersenzkproof test", func() {
	p := big.NewInt(43)
	q := big.NewInt(59)
	eulerValue := new(big.Int).Mul(big.NewInt(42), big.NewInt(58))
	n := new(big.Int).Mul(p, q)
	// r = 2
	t := big.NewInt(4)
	lambda := big.NewInt(3)
	s := big.NewInt(64)
	ssIDInfo := []byte("Mark HaHa")

	Context("It is OK", func() {
		It("over Range, should be ok", func() {
			zkproof, err := NewRingPederssenParameterMessage(ssIDInfo, eulerValue, n, s, t, lambda, MINIMALCHALLENGE)
			Expect(err).Should(BeNil())
			err = zkproof.Verify(ssIDInfo)
			Expect(err).Should(BeNil())
		})
	})

	Context("Error handle", func() {
		It("negative eulerValue", func() {
			zkproof, err := NewRingPederssenParameterMessage(ssIDInfo, big.NewInt(-1), n, s, t, lambda, MINIMALCHALLENGE)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})

		It("the number of MINIMALCHALLENGE too small", func() {
			zkproof, err := NewRingPederssenParameterMessage(ssIDInfo, big.NewInt(-1), n, s, t, lambda, 1)
			Expect(err).ShouldNot(BeNil())
			Expect(zkproof).Should(BeNil())
		})
	})

	Context("It is OK", func() {
		var zkproof *RingPederssenParameterMessage
		BeforeEach(func() {
			var err error
			zkproof, err = NewRingPederssenParameterMessage(ssIDInfo, eulerValue, n, s, t, lambda, MINIMALCHALLENGE)
			Expect(err).Should(BeNil())
		})

		It("the number of MINIMALCHALLENGE too small", func() {
			zkproof.A = zkproof.A[0:1]
			err := zkproof.Verify(ssIDInfo)
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong range of A", func() {
			zkproof.A[0] = zkproof.N
			err := zkproof.Verify(ssIDInfo)
			Expect(err).ShouldNot(BeNil())
		})

		It("not coprime A and p", func() {
			zkproof.A[0] = new(big.Int).Set(p).Bytes()
			err := zkproof.Verify(ssIDInfo)
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong range of Z", func() {
			zkproof.Z[0] = zkproof.N
			err := zkproof.Verify(ssIDInfo)
			Expect(err).ShouldNot(BeNil())
		})

		It("verify failure", func() {
			zkproof.Z[0] = big1.Bytes()
			err := zkproof.Verify(ssIDInfo)
			Expect(err).ShouldNot(BeNil())
		})
	})

})
