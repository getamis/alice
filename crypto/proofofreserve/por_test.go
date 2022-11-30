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

package por

import (
	"math/big"
	"strconv"
	"testing"

	. "github.com/onsi/ginkgo"
	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func TestPOR(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "POR Test")
}

var _ = Describe("Sign test", func() {
	NumberUser := 10
	userInfo := make(map[string]*big.Int)
	for i := 0; i < NumberUser; i++ {
		userInfo[strconv.Itoa(i)] = big.NewInt(int64(i))
	}
	rangeProofUpBound := uint(64)
	pointMsg := []byte("Amy Haha")
	// Generate public key i.e. pointMsg is a string determined by us.
	pubKey, _ := GenerateCommitmentPubKey(pointMsg, rangeProofUpBound)
	It("Correct case", func() {
		// Generate all proofs.
		porCommitment, err := pubKey.GenerateCommitmentData(userInfo)
		Expect(err).Should(BeNil())
		// Single User verify: own commitment and range proof.
		checkUser := strconv.Itoa(1)
		err = porCommitment.userInfo[checkUser].userVerifyOwnCommitment(checkUser, userInfo[checkUser], pubKey, porCommitment.userProof[checkUser])
		Expect(err).Should(BeNil())
		// Verify the amount of assets of all users is correct!
		err = pubKey.VerifyTotalReserve(porCommitment)
		Expect(err).Should(BeNil())
	})

	// Measure("the benchmark performance of GenerateCommitmentData", func(b Benchmarker) {
	// 	NumberUser := 1
	// 	userInfo := make(map[string]*big.Int)
	// 	for i := 0; i < NumberUser; i++ {
	// 		userInfo[strconv.Itoa(i)] = big.NewInt(int64(i))
	// 	}
	// 	rangeProofUpBound := uint(64)
	// 	pointMsg := []byte("Amy Haha")
	// 	pubKey, _ := GenerateCommitmentPubKey(pointMsg, rangeProofUpBound)

	// 	runtime := b.Time("Generate Commitment Estimation", func() {
	// 		pubKey.GenerateCommitmentData(userInfo)
	// 	})

	// 	Expect(runtime.Nanoseconds()).Should(BeNumerically("<", (100 * time.Second).Nanoseconds()))

	// 	b.RecordValue("Execution time in microseconds", float64(runtime.Nanoseconds()/1000))
	// },
	// 	100)
})
