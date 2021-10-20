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

package blssignature

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"

	. "github.com/onsi/ginkgo"
	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestBlsSignature(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BlsSignature Test")
}

var _ = Describe("Sign test", func() {
	It("Correct case", func() {
		nthreshold := uint32(2)
		bk1 := birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0)
		bk2 := birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0)
		allbk := birkhoffinterpolation.BkParameters{bk1, bk2}
		privateKey := big.NewInt(100)
		share1 := big.NewInt(102)
		share2 := big.NewInt(104)
		message := make([]byte, 2*48)
		pubKey := g1.MulScalarBig(blsEngine.G1.New(), blsEngine.G1.One(), privateKey)

		p1, err := NewParticipant(nthreshold, message, share1, pubKey, bk1, allbk)
		Expect(err).Should(BeNil())
		p2, err := NewParticipant(nthreshold, message, share2, pubKey, bk2, allbk)
		Expect(err).Should(BeNil())

		partialSig1, err := p1.Sign()
		Expect(err).Should(BeNil())
		partialSig2, err := p2.Sign()
		Expect(err).Should(BeNil())

		partialSigs := [][]byte{partialSig1, partialSig2}
		sig1, err := p1.GetSignature(partialSigs)
		Expect(err).Should(BeNil())
		sig2, err := p2.GetSignature(partialSigs)
		Expect(err).Should(BeNil())
		Expect(sig1).Should(Equal(sig2))
		got, err := g2.FromCompressed(sig1)
		Expect(err).Should(BeNil())
		err = verifySignature(got, pubKey, p1.messagePoint)
		Expect(err).Should(BeNil())
	})
})
