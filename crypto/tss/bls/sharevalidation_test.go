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
			shareValManager := make([]*ShareValidation, totalNumber)
			poly, err := polynomial.RandomPolynomial(bls12381CurveOrder, threshold-1)
			Expect(err).Should(BeNil())
			secret := poly.Evaluate(big.NewInt(0))
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(secret)
			pubKeyByte := pubKey.Bytes()

			for i := 0; i < len(shareValManager); i++ {
				tempX, err := utils.RandomPositiveInt(bls12381CurveOrder)
				Expect(err).Should(BeNil())
				bkSS[i] = birkhoffinterpolation.NewBkParameter(tempX, 0)
				tempShareValidaitonManager, err := NewShareValidationManager(threshold, poly.Evaluate(tempX).Bytes(), bkSS[i], pubKeyByte[:])
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

	Context("Negative Cases", func() {
		It("the length of public Key is too large", func() {
			pubKey := make([]byte, 100)
			_, err := NewShareValidationManager(3, big1.Bytes(), nil, pubKey)
			Expect(err).Should(Equal(ErrWrongLengthPubKey))
		})

		It("wrong threshold", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewShareValidationManager(3, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.ComputeShareProof([]byte(""))
			Expect(err).Should(BeNil())
			err = tempManager.Validation([]*ShareValidationMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong public Key for message", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewShareValidationManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.ComputeShareProof([]byte(""))
			Expect(err).Should(BeNil())
			msg1.PublicKey = []byte{1}
			err = tempManager.Validation([]*ShareValidationMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong public Key for Manager", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewShareValidationManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.ComputeShareProof([]byte(""))
			Expect(err).Should(BeNil())
			tempManager.pubKey = []byte{1}
			err = tempManager.Validation([]*ShareValidationMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("the length of public Key for Manager is too large", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewShareValidationManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.ComputeShareProof([]byte(""))
			Expect(err).Should(BeNil())
			msg1.PartialPubKey = make([]byte, 100)
			err = tempManager.Validation([]*ShareValidationMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong partial-public Key for shareManager", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewShareValidationManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.ComputeShareProof([]byte(""))
			Expect(err).Should(BeNil())
			tempManager.partialPubKey = []byte{1}
			err = tempManager.Validation([]*ShareValidationMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong partial-public Key for message", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewShareValidationManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.ComputeShareProof([]byte(""))
			Expect(err).Should(BeNil())
			msg1.PartialPubKey = []byte{1}
			err = tempManager.Validation([]*ShareValidationMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("BK wrong: X > curveOrder", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewShareValidationManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.ComputeShareProof([]byte(""))
			Expect(err).Should(BeNil())
			msg1.Bk.X = new(big.Int).Add(big1, bls12381CurveOrder).Bytes()
			err = tempManager.Validation([]*ShareValidationMessage{msg1})
			Expect(err).ShouldNot(BeNil())
		})

		It("the length of pubKey is too large", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big.NewInt(100))
			pubKeyByte := pubKey.Bytes()
			tempManager, err := NewShareValidationManager(1, big1.Bytes(), birkhoffinterpolation.NewBkParameter(big1, 0), pubKeyByte[:])
			Expect(err).Should(BeNil())
			msg1, err := tempManager.ComputeShareProof([]byte(""))
			Expect(err).Should(BeNil())
			err = tempManager.Validation([]*ShareValidationMessage{msg1})
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

		It("Schnorr verification: wrong pubKey", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			proof, err := NewG1SchnorrZkProof(big1, pubKeyByte[:], []byte("Vick Haha"))
			err = proof.Verify([]byte("LLLL"))
			Expect(err).ShouldNot(BeNil())
		})

		It("Schnorr verification: the length of the public Key is too large", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			proof, err := NewG1SchnorrZkProof(big1, pubKeyByte[:], []byte("Vick Haha"))
			wrongPubKey := make([]byte, 100)
			err = proof.Verify(wrongPubKey)
			Expect(err).ShouldNot(BeNil())
		})

		It("Schnorr verification", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			proof, err := NewG1SchnorrZkProof(big1, pubKeyByte[:], []byte("Vick Haha"))
			proof.R = new(big.Int).Add(bls12381CurveOrder, big1).Bytes()
			err = proof.Verify(pubKeyByte[:])
			Expect(err).ShouldNot(BeNil())
		})

		It("wrong Schnorr verification", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			proof, err := NewG1SchnorrZkProof(big1, pubKeyByte[:], []byte("Vick Haha"))
			proof.V = make([]byte, 100)
			err = proof.Verify(pubKeyByte[:])
			Expect(err).ShouldNot(BeNil())
		})

		It("Schnorr verification: wrong proof", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			proof, err := NewG1SchnorrZkProof(big1, pubKeyByte[:], []byte("Vick Haha"))
			proof.V = []byte{1}
			err = proof.Verify(pubKeyByte[:])
			Expect(err).ShouldNot(BeNil())
		})

		It("Schnorr verification: wrong R", func() {
			pubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big1)
			pubKeyByte := pubKey.Bytes()
			proof, err := NewG1SchnorrZkProof(big1, pubKeyByte[:], []byte("Vick Haha"))
			proof.R = big.NewInt(3).Bytes()
			err = proof.Verify(pubKeyByte[:])
			Expect(err).ShouldNot(BeNil())
		})
	})
})
