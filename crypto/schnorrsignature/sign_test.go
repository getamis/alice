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

package schnorrsignature

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"

	"github.com/getamis/alice/crypto/elliptic"
	edwards "github.com/decred/dcrd/dcrec/edwards"

	. "github.com/onsi/ginkgo"

	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var (
	edd25519 = elliptic.NewEd25519()
)

var _ = Describe("Sign test", func() {
	It("Correct case", func() {
		nthreshold := uint32(2)
		bk1 := birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0)
		bk2 := birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0)
		allbk := birkhoffinterpolation.BkParameters{bk1, bk2}
		privateKey := big.NewInt(100)
		share1 := big.NewInt(102)
		share2 := big.NewInt(104)
		message := []byte("8077818")
		pubKey := ecpointgrouplaw.ScalarBaseMult(edd25519, privateKey)

		p1 := NewParticipant(nthreshold, share1, message, bk1, pubKey, allbk)
		p2 := NewParticipant(nthreshold, share2, message, bk2, pubKey, allbk)

		p1round0Msg, err := p1.Round0()
		Expect(err).Should(BeNil())
		p2round0Msg, err := p2.Round0()
		Expect(err).Should(BeNil())
		round0Msg := []*CommitmentMsg{p1round0Msg, p2round0Msg}
		p1round1Msg, err := p1.Round1(round0Msg)
		Expect(err).Should(BeNil())
		p2round1Msg, err := p2.Round1(round0Msg)
		Expect(err).Should(BeNil())
		round1Msg := []*PartialSignatureMsg{p1round1Msg, p2round1Msg}
		R1, s1, err := p1.Round2(round1Msg)
		Expect(err).Should(BeNil())
		R2, s2, err := p2.Round2(round1Msg)
		Expect(err).Should(BeNil())
		Expect(R1.Equal(R2)).Should(BeTrue())
		Expect(s1.Cmp(s2) == 0).Should(BeTrue())

		edwardPubKey := edwards.NewPublicKey(edwards.Edwards(), pubKey.GetX(), pubKey.GetY())

		test1 := ecpointEncoding(R1)
		test2 := *test1
		r := new(big.Int).SetBytes(utils.ReverseByte(test2[:]))
		fmt.Println("tse", ecpointEncoding(R1))

		//edward25519.Verify()
		got := edwards.Verify(edwardPubKey, message, r, s1)
		Expect(got).Should(BeTrue())
	})
})

func TestSchnorrsignature(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Schnorrsignature Test")
}
