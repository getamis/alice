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
	"testing"

	"github.com/OffchainLabs/prysm/v6/crypto/bls/blst"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("bls MPC Sign", func() {
	Context("It is OK", func() {
		It("Sign", func() {
			threshold := uint32(3)
			totalNumber := uint32(5)
			msg, err := utils.GenRandomBytes(32)
			Expect(err).Should(BeNil())
			bkSS := make([]*birkhoffinterpolation.BkParameter, totalNumber)
			signManager := make([]*SignManager, totalNumber)
			poly, err := polynomial.RandomPolynomial(bls12381CurveOrder, threshold-1)
			Expect(err).Should(BeNil())
			secret := poly.Evaluate(big.NewInt(0))
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(secret)
			pubKeyByte := pubKey.Bytes()

			for i := 0; i < len(signManager); i++ {
				tempX, err := utils.RandomPositiveInt(bls12381CurveOrder)
				Expect(err).Should(BeNil())
				bkSS[i] = birkhoffinterpolation.NewBkParameter(tempX, 0)
				tempManager, err := NewSignManager(threshold, poly.Evaluate(tempX).Bytes(), bkSS[i], pubKeyByte[:])
				Expect(err).Should(BeNil())
				signManager[i] = tempManager
			}
			signMsg := make([]*SignMessage, totalNumber)

			for i := 0; i < len(signManager); i++ {
				tempMsg, err := signManager[i].Sign(msg)
				Expect(err).Should(BeNil())
				signMsg[i] = tempMsg
			}
			// Validation
			var mpcSignature []byte
			for i := 0; i < len(signManager); i++ {
				mpcSignature, err = signManager[i].RecoverMPCSignature(signMsg)
				Expect(err).Should(BeNil())
			}
			// prysm Sign: Check the same pubKey and the same Signature
			secretKey, err := blst.SecretKeyFromBytes(secret.Bytes())
			Expect(err).Should(BeNil())
			Expect(secretKey.PublicKey().Marshal()).Should(Equal(pubKeyByte[:]))
			prysmSig := secretKey.Sign(msg).Marshal()
			Expect(prysmSig).Should(Equal(mpcSignature[:]))
		})
	})

	Context("Negative Cases", func() {
		It("paring failure", func() {
			var wrongG1 bls12381.G1Affine
			var wrongG2 bls12381.G2Affine
			wrongG1.ScalarMultiplicationBase(big.NewInt(3))
			wrongG2.ScalarMultiplicationBase(big.NewInt(2))
			err := verificationSignature(wrongG2, wrongG1, wrongG2)
			Expect(err).Should(Equal(ErrFailureSign))
		})

		It("wrong public Key ", func() {
			pubKey := make([]byte, 100)
			_, err := NewSignManager(3, big1.Bytes(), nil, pubKey)
			Expect(err).Should(Equal(ErrWrongLengthPubKey))
		})

		It("wrong threshold", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewSignManager(3, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.Sign([]byte(""))
			Expect(err).Should(BeNil())
			_, err = tempManager.RecoverMPCSignature([]*SignMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("the length of the public Key is too large", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewSignManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.Sign([]byte(""))
			Expect(err).Should(BeNil())
			msg1.PublicKey = make([]byte, 100)
			_, err = tempManager.RecoverMPCSignature([]*SignMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong signature", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewSignManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.Sign([]byte(""))
			Expect(err).Should(BeNil())
			msg1.Signature = make([]byte, 100)
			_, err = tempManager.RecoverMPCSignature([]*SignMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong verification", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big.NewInt(100))
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewSignManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.Sign([]byte(""))
			Expect(err).Should(BeNil())
			_, err = tempManager.RecoverMPCSignature([]*SignMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})
	})
})

func TestBlsMPC(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sign Suite")
}
