// Copyright © 2025 AMIS Technologies
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

package bls

import (
	"crypto/subtle"
	"errors"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
)

const (
	G1MaxByteLength = 48
	G2MaxByteLength = 96
)

var (
	dst                   = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
	big1                  = big.NewInt(1)
	bls12381CurveOrder, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)

	// ErrZeroMessage is returned if the hash point is the identity point.
	ErrZeroMessage = errors.New("the hash point is the identity point")
	// ErrFailureSign is returned if the verification of signature failures.
	ErrFailureSign = errors.New("the verification of signature failures")
	// ErrPubKeyDifferent is returned if the public key are different.
	ErrPubKeyDifferent = errors.New("the public key are different")
	// ErrWrongLengthPubKey is returned if the length of public key is wrong.
	ErrWrongLengthPubKey = errors.New("the length of public key is wrong")
	// ErrShareValidationFailure is returned if the validation of shares failures.
	ErrShareValidationFailure = errors.New("the validation of shares failures")
)

type SignManager struct {
	ownBK     *birkhoffinterpolation.BkParameter
	threshold uint32
	// 0 < share < bls12381CurveOrder
	ownShare *big.Int
	// 96 bytes
	pubKey           *bls12381.G1Affine
	partialSignature []byte
	msgPoint         bls12381.G2Affine
}

func NewSignManager(threshold uint32, share []byte, bk *birkhoffinterpolation.BkParameter, pubKey []byte) (*SignManager, error) {
	// check the correctness of share and pubKey
	bshare, pubKeyG1, err := validationShareAndPubKey(share, pubKey)
	if err != nil {
		return nil, err
	}
	return &SignManager{
		ownBK:     bk,
		threshold: threshold,
		ownShare:  bshare,
		pubKey:    pubKeyG1,
	}, nil
}

func (sM *SignManager) Sign(msg []byte) (*SignMessage, error) {
	h, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		return nil, err
	}
	if h.IsInfinity() {
		return nil, ErrZeroMessage
	}
	var signature bls12381.G2Affine
	signature.ScalarMultiplication(&h, sM.ownShare)
	partialPubKey := new(bls12381.G1Affine).ScalarMultiplicationBase(sM.ownShare)
	// verification e(H(m), pubKey) = e(sign, g2)
	err = verificationSignature(h, *partialPubKey, signature)
	if err != nil {
		return nil, err
	}
	resultByte := signature.Bytes()
	pubKeyByte := sM.pubKey.Bytes()
	resultMsg := &SignMessage{
		Signature: resultByte[:],
		PublicKey: pubKeyByte[:],
		Bk:        sM.ownBK.ToMessage(),
	}
	sM.partialSignature = resultByte[:]
	sM.msgPoint = h
	return resultMsg, nil
}

func (sM *SignManager) RecoverMPCSignature(signMsg []*SignMessage) ([G2MaxByteLength]byte, error) {
	zeroByte := [G2MaxByteLength]byte{}
	bkss := birkhoffinterpolation.BkParameters{
		sM.ownBK,
	}
	signSlice := make([][]byte, 1)
	signSlice[0] = sM.partialSignature
	pubKeyByte := sM.pubKey.Bytes()

	// check the correctness of the partial signatures
	for i := 0; i < len(signMsg); i++ {
		tempSign := signMsg[i].Signature
		// The length of a correct signature is 96
		if len(tempSign) > G2MaxByteLength {
			return zeroByte, ErrFailureSign
		}
		signSlice = append(signSlice, tempSign)
		tempBks, err := signMsg[i].Bk.ToBk(bls12381CurveOrder)
		if err != nil {
			return zeroByte, err
		}
		bkss = append(bkss, tempBks)
		getPubKey := signMsg[i].PublicKey
		if subtle.ConstantTimeCompare(pubKeyByte[:], getPubKey) != 1 {
			return zeroByte, ErrPubKeyDifferent
		}
	}
	bkCoefficient, err := bkss.ComputeBkCoefficient(sM.threshold, bls12381CurveOrder)
	if err != nil {
		return zeroByte, err
	}
	var result bls12381.G2Affine
	_, err = result.SetBytes(signSlice[0])
	if err != nil {
		return zeroByte, err
	}
	result.ScalarMultiplication(&result, bkCoefficient[0])
	for i := 1; i < len(signSlice); i++ {
		var temp bls12381.G2Affine
		_, err = temp.SetBytes(signSlice[i])
		if err != nil {
			return zeroByte, err
		}
		temp.ScalarMultiplication(&temp, bkCoefficient[i])
		result.Add(&result, &temp)
	}
	// check the final signature
	err = verificationSignature(sM.msgPoint, *sM.pubKey, result)
	if err != nil {
		return zeroByte, err
	}
	return result.Bytes(), nil
}

func verificationSignature(msgPoint bls12381.G2Affine, pubKey bls12381.G1Affine, sig bls12381.G2Affine) error {
	// verification e(pubKey, H(m)) = e(g1, sign)
	e1, err := bls12381.Pair([]bls12381.G1Affine{pubKey}, []bls12381.G2Affine{msgPoint})
	if err != nil {
		return err
	}
	e2, err := bls12381.Pair([]bls12381.G1Affine{*new(bls12381.G1Affine).ScalarMultiplicationBase(big1)}, []bls12381.G2Affine{sig})
	if err != nil {
		return nil
	}
	if !e1.Equal(&e2) {
		return ErrFailureSign
	}
	return nil
}
