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

package bulletproof

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"

	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestBulletProofPlus(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TestBulletProofPlus Test")
}

var _ = Describe("Positive test", func() {
	G := g2.One()
	n := uint(64)
	order := g2.Q()
	H := g2.MulScalarBig(blsEngine.G2.New(), G2, big.NewInt(2))
	secret := big.NewInt(0)
	// Remark that secret < 2^n
	random, _ := utils.RandomPositiveInt(order)
	C := g2.MulScalarBig(blsEngine.G2.New(), G, secret)
	g2.Add(C, C, g2.MulScalarBig(blsEngine.G2.New(), H, random))
	It("Correct case", func() {
		publicParameter, err := NewPublicParameter(G, H, n)
		prover := NewProver(publicParameter, secret, random, C)
		Expect(err).Should(BeNil())
		proverMsg, err := prover.InitialProveData()
		Expect(err).Should(BeNil())
		err = proverMsg.Verify(publicParameter, C)
		Expect(err).Should(BeNil())
	})
})
