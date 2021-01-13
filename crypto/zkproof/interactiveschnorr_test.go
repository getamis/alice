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
package zkproof

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Interactive Schnorr 5 moves", func() {
	var (
		G = pt.ScalarBaseMult(btcec.S256(), big.NewInt(1))
	)

	DescribeTable("should be ok", func(a *big.Int) {
		// step 1: The prover randomly chooses an integer k in [1, p-1] and sends H := k*G and V to the verifier.
		p, err := NewInteractiveSchnorrProver(a, G)
		Expect(err).Should(BeNil())
		pmsg1 := p.GetInteractiveSchnorrProver1Message()

		// step 2: The verifier randomly chooses two integers r, e in [0,p-1] and sends C:= r*G + e*H.
		v, err := NewInteractiveSchnorrVerifier(pmsg1)
		vmsg1 := v.GetInteractiveSchnorrVerifier1Message()
		p.SetCommitC(vmsg1)

		// step 3: The prover randomly chooses an integer a in [1, p-1] sends B := a*G to verifier.
		pmsg2, err := p.GetInteractiveSchnorrProver2Message()
		Expect(err).Should(BeNil())
		err = v.SetB(pmsg2)
		Expect(err).Should(BeNil())

		// step 4: The verifier sends (e,r) to the prover.
		vmsg2 := v.GetInteractiveSchnorrVerifier2Message()

		// step 5: The prover verifies e in [0,p-1], r in [0,p-1], and C = r*G + e*H, and computes z = a + ex mod p and sends k, z to prover.
		vmsg3, err := p.ComputeZ(vmsg2)
		Expect(err).Should(BeNil())

		// step 6: The verifier verifies z in [0,p-1], k in [1, p-1], H = k*G, and z*G = B + e*V
		err = v.Verify(vmsg3)
		Expect(err).Should(BeNil())
	},
		Entry("Curve: S256 #1", big.NewInt(1213121351352)),
		Entry("Curve: S256 #2", big.NewInt(1351352)),
	)

	Context("ComputeZ", func() {
		It("C != eH+rG", func() {
			a := big.NewInt(578)
			p, err := NewInteractiveSchnorrProver(a, G)
			Expect(err).Should(BeNil())
			pmsg1 := p.GetInteractiveSchnorrProver1Message()
			v, err := NewInteractiveSchnorrVerifier(pmsg1)
			Expect(err).Should(BeNil())
			vmsg1 := v.GetInteractiveSchnorrVerifier1Message()
			p.SetCommitC(vmsg1)
			pmsg2, err := p.GetInteractiveSchnorrProver2Message()
			Expect(err).Should(BeNil())
			err = v.SetB(pmsg2)
			Expect(err).Should(BeNil())
			vmsg2 := v.GetInteractiveSchnorrVerifier2Message()
			p.c = G.Copy()
			vmsg3, err := p.ComputeZ(vmsg2)
			Expect(vmsg3).Should(BeNil())
			Expect(err).Should(Equal(ErrVerifyFailure))
		})

		It("e out of range", func() {
			a := big.NewInt(996)
			p, err := NewInteractiveSchnorrProver(a, G)
			Expect(err).Should(BeNil())
			pmsg1 := p.GetInteractiveSchnorrProver1Message()
			v, err := NewInteractiveSchnorrVerifier(pmsg1)
			Expect(err).Should(BeNil())
			vmsg1 := v.GetInteractiveSchnorrVerifier1Message()
			p.SetCommitC(vmsg1)
			pmsg2, err := p.GetInteractiveSchnorrProver2Message()
			Expect(err).Should(BeNil())
			err = v.SetB(pmsg2)
			Expect(err).Should(BeNil())
			vmsg2 := v.GetInteractiveSchnorrVerifier2Message()
			vmsg2.E = []byte("222092378402958308234579287598237592295870923582390572039573920573025723095702395790235720395720395792305720351")
			vmsg3, err := p.ComputeZ(vmsg2)
			Expect(vmsg3).Should(BeNil())
			Expect(err).Should(Equal(ErrVerifyFailure))
		})

		It("r out of range", func() {
			a := big.NewInt(5566)
			p, err := NewInteractiveSchnorrProver(a, G)
			Expect(err).Should(BeNil())
			pmsg1 := p.GetInteractiveSchnorrProver1Message()
			v, err := NewInteractiveSchnorrVerifier(pmsg1)
			vmsg1 := v.GetInteractiveSchnorrVerifier1Message()
			p.SetCommitC(vmsg1)
			pmsg2, err := p.GetInteractiveSchnorrProver2Message()
			Expect(err).Should(BeNil())
			err = v.SetB(pmsg2)
			Expect(err).Should(BeNil())
			vmsg2 := v.GetInteractiveSchnorrVerifier2Message()
			vmsg2.R = []byte("222092378402958308234579287598237592295870923582390572039573920573025723095702395790235720395720395792305720351")
			vmsg3, err := p.ComputeZ(vmsg2)
			Expect(vmsg3).Should(BeNil())
			Expect(err).Should(Equal(ErrVerifyFailure))
		})
	})

	Context("Verify", func() {
		It("z*G != B + e*V", func() {
			a := big.NewInt(12)
			p, err := NewInteractiveSchnorrProver(a, G)
			Expect(err).Should(BeNil())
			pmsg1 := p.GetInteractiveSchnorrProver1Message()
			v, err := NewInteractiveSchnorrVerifier(pmsg1)
			Expect(err).Should(BeNil())
			vmsg1 := v.GetInteractiveSchnorrVerifier1Message()
			p.SetCommitC(vmsg1)
			pmsg2, err := p.GetInteractiveSchnorrProver2Message()
			Expect(err).Should(BeNil())
			err = v.SetB(pmsg2)
			Expect(err).Should(BeNil())
			vmsg2 := v.GetInteractiveSchnorrVerifier2Message()
			vmsg3, err := p.ComputeZ(vmsg2)
			Expect(err).Should(BeNil())

			vmsg3.Z = []byte("222")
			err = v.Verify(vmsg3)
			Expect(err).Should(Equal(ErrVerifyFailure))
		})

		It("H != k*G", func() {
			a := big.NewInt(12)
			p, err := NewInteractiveSchnorrProver(a, G)
			Expect(err).Should(BeNil())
			pmsg1 := p.GetInteractiveSchnorrProver1Message()
			v, err := NewInteractiveSchnorrVerifier(pmsg1)
			Expect(err).Should(BeNil())
			vmsg1 := v.GetInteractiveSchnorrVerifier1Message()
			p.SetCommitC(vmsg1)
			pmsg2, err := p.GetInteractiveSchnorrProver2Message()
			Expect(err).Should(BeNil())
			err = v.SetB(pmsg2)
			Expect(err).Should(BeNil())
			vmsg2 := v.GetInteractiveSchnorrVerifier2Message()
			vmsg3, err := p.ComputeZ(vmsg2)
			Expect(err).Should(BeNil())

			vmsg3.K = []byte("222")
			err = v.Verify(vmsg3)
			Expect(err).Should(Equal(ErrVerifyFailure))
		})

		It("Z out of range", func() {
			a := big.NewInt(12)
			p, err := NewInteractiveSchnorrProver(a, G)
			Expect(err).Should(BeNil())
			pmsg1 := p.GetInteractiveSchnorrProver1Message()
			v, err := NewInteractiveSchnorrVerifier(pmsg1)
			Expect(err).Should(BeNil())
			vmsg1 := v.GetInteractiveSchnorrVerifier1Message()
			p.SetCommitC(vmsg1)
			pmsg2, err := p.GetInteractiveSchnorrProver2Message()
			Expect(err).Should(BeNil())
			err = v.SetB(pmsg2)
			Expect(err).Should(BeNil())
			vmsg2 := v.GetInteractiveSchnorrVerifier2Message()
			vmsg3, err := p.ComputeZ(vmsg2)
			Expect(err).Should(BeNil())
			vmsg3.Z = []byte("222092378402958308234579287598237592295870923582390572039573920573025723095702395790235720395720395792305720351")
			err = v.Verify(vmsg3)
			Expect(err).Should(Equal(ErrVerifyFailure))
		})

		It("k out of range", func() {
			a := big.NewInt(12)
			p, err := NewInteractiveSchnorrProver(a, G)
			Expect(err).Should(BeNil())
			pmsg1 := p.GetInteractiveSchnorrProver1Message()
			v, err := NewInteractiveSchnorrVerifier(pmsg1)
			Expect(err).Should(BeNil())
			vmsg1 := v.GetInteractiveSchnorrVerifier1Message()
			p.SetCommitC(vmsg1)
			pmsg2, err := p.GetInteractiveSchnorrProver2Message()
			Expect(err).Should(BeNil())
			err = v.SetB(pmsg2)
			Expect(err).Should(BeNil())
			vmsg2 := v.GetInteractiveSchnorrVerifier2Message()
			vmsg3, err := p.ComputeZ(vmsg2)
			Expect(err).Should(BeNil())
			vmsg3.K = []byte("222092378402958308234579287598237592295870923582390572039573920573025723095702395790235720395720395792305720351")
			err = v.Verify(vmsg3)
			Expect(err).Should(Equal(ErrVerifyFailure))
		})
	})
})
