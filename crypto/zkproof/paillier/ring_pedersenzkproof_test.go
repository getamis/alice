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
			z0 := new(big.Int).SetBytes(zkproof.Z[0])
			z0.Add(z0, big.NewInt(1))
			zkproof.Z[0] = z0.Bytes()
			err := zkproof.Verify(ssIDInfo)
			Expect(err).ShouldNot(BeNil())
		})
		It("statement N is an invalid even number", func() {
			originalN := new(big.Int).SetBytes(zkproof.N)
			evenN := new(big.Int).Mul(originalN, big2)

			zkproof.N = evenN.Bytes()
			err := zkproof.Verify(ssIDInfo)
			Expect(err).Should(Equal(ErrVerifyFailure))
		})

		It("statement S is out of range", func() {
			currentN := new(big.Int).SetBytes(zkproof.N)
			invalidS := new(big.Int).Add(currentN, big1)

			zkproof.S = invalidS.Bytes()
			err := zkproof.Verify(ssIDInfo)
			Expect(err).Should(Equal(ErrVerifyFailure))
		})

		It("statement T is out of range", func() {
			currentN := new(big.Int).SetBytes(zkproof.N)
			invalidT := new(big.Int).Add(currentN, big1)

			zkproof.T = invalidT.Bytes()
			err := zkproof.Verify(ssIDInfo)
			Expect(err).Should(Equal(ErrVerifyFailure))
		})

		It("msg.A element byte length too large (OOM protection)", func() {
			maxElementByteLen := len(n.Bytes()) + 2
			zkproof.A[0] = make([]byte, maxElementByteLen+10)

			err := zkproof.Verify(ssIDInfo)
			Expect(err).ShouldNot(BeNil())
		})

		It("msg.Z element byte length too large (OOM protection)", func() {
			maxElementByteLen := len(n.Bytes()) + 2
			zkproof.Z[0] = make([]byte, maxElementByteLen+10)

			err := zkproof.Verify(ssIDInfo)
			Expect(err).ShouldNot(BeNil())
		})
	})

})
