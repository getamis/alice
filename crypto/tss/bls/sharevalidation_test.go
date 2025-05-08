// Copyright © 2025 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package bls

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("bls mpc share validation", func() {
	Context("It is OK", func() {
		It("Share Validation", func() {
			threshold := uint32(3)
			totalNumber := uint32(5)
			msg := []byte("Time")
			bkSS := make([]*birkhoffinterpolation.BkParameter, totalNumber)
			shareValManager := make([]*ShareValidaiton, totalNumber)
			poly, err := polynomial.RandomPolynomial(bls12381CurveOrder, threshold-1)
			Expect(err).Should(BeNil())
			secret := poly.Evaluate(big.NewInt(0))
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(secret)
			pubKeyByte := pubKey.Bytes()

			for i := 0; i < len(shareValManager); i++ {
				tempX, err := utils.RandomPositiveInt(bls12381CurveOrder)
				Expect(err).Should(BeNil())
				bkSS[i] = birkhoffinterpolation.NewBkParameter(tempX, 0)
				tempShareValidaitonManager, err := NewShareValidaitonManager(threshold, poly.Evaluate(tempX).Bytes(), bkSS[i], pubKeyByte[:])
				Expect(err).Should(BeNil())
				shareValManager[i] = tempShareValidaitonManager
			}
			shareValidaitonMsg := make([]*ShareValidationMessage, totalNumber)

			for i := 0; i < len(shareValManager); i++ {
				tempMsg, err := shareValManager[i].ComputeShareProof(msg)
				Expect(err).Should(BeNil())
				shareValidaitonMsg[i] = tempMsg
			}
			// Validation
			for i := 0; i < len(shareValManager); i++ {
				err = shareValManager[i].Validation(shareValidaitonMsg)
				Expect(err).Should(BeNil())
			}
		})
	})
})
