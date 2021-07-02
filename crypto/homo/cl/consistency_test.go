// Copyright © 2021 AMIS Technologies
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

package cl

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Consistency proof", func() {
	var cl *CL
	bigPrime, _ := new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)
	safeParameter := 1348

	BeforeEach(func() {
		// Generate a private key and the public key associated with discriminant bigPrime * q, where
		// bigPrime is the message space and q is a probabilistic "prime" with the bitlength is SAFEPARAMETER - bitlength of bigprime.
		var err error
		cl, err = NewCL(big.NewInt(1024), 40, bigPrime, safeParameter, 40)
		Expect(err).Should(BeNil())
	})

	It("it is ok", func() {
		plaintext := big.NewInt(100).Bytes()
		R := pt.NewBase(btcec.S256())
		encryptMsg, err := cl.BuildConsistencyProof(plaintext, R)
		Expect(err).Should(BeNil())
		err = cl.VerifyConsistencyProof(encryptMsg)
		Expect(err).Should(BeNil())
	})

	It("point does not equal", func() {
		plaintext := big.NewInt(100)
		c1, c2, r, err := cl.encrypt(plaintext)
		Expect(err).Should(BeNil())
		R := pt.NewBase(btcec.S256())
		Q := R.ScalarMult(big.NewInt(123))
		proof, err := cl.buildProofWithPointQ(plaintext, r, Q, R)
		Expect(err).Should(BeNil())
		msgR, err := R.ToEcPointMessage()
		Expect(err).Should(BeNil())
		encrypMsg := &ConsistencyProofMessage{
			C1:    c1,
			C2:    c2,
			Proof: proof,
			R:     msgR,
		}
		err = cl.VerifyConsistencyProof(encrypMsg)
		Expect(err).Should(Equal(ErrFailedVerify))
	})
})
