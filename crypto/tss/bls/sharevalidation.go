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
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
)

var (
	big0 = big.NewInt(0)

	
	// ErrSchnorrFailure is returned if the verification of Schnorr's ZK failures.
	ErrSchnorrFailure = errors.New("the verification of Schnorr's ZK failures")
)

type ShareValidation struct {
	ownBK     *birkhoffinterpolation.BkParameter
	threshold uint32
	ownShare  *big.Int
	pubKey    []byte

	partialPubKey []byte
}

func NewShareValidationManager(threshold uint32, share []byte, bk *birkhoffinterpolation.BkParameter, pubKey []byte) (*ShareValidation, error) {
	// check the correctness of share and pubKey
	bshare, _, err := validationShareAndPubKey(share, pubKey)
	if err != nil {
		return nil, err
	}
	return &ShareValidation{
		ownBK:     bk,
		threshold: threshold,
		ownShare:  bshare,
		pubKey:    pubKey,
	}, nil
}

func (sV *ShareValidation) ComputeShareProof(schnorrInfo []byte) (*ShareValidationMessage, error) {
	// compute sharePoint
	var partialPubKey bls12381.G1Affine
	partialPubKey.ScalarMultiplicationBase(sV.ownShare)
	partialPubKeyByte := partialPubKey.Bytes()

	// compute Schnorr Zk
	proof, err := NewG1SchnorrZkProof(sV.ownShare, partialPubKeyByte[:], schnorrInfo)
	if err != nil {
		return nil, err
	}

	// Set data
	sV.partialPubKey = partialPubKeyByte[:]

	return &ShareValidationMessage{
		PartialPubKey: partialPubKeyByte[:],
		PublicKey:     sV.pubKey,
		Bk:            sV.ownBK.ToMessage(),
		Proof:         proof,
	}, nil
}

func (sV *ShareValidation) Validation(partialPubKeyMsg []*ShareValidationMessage) error {
	bkss := birkhoffinterpolation.BkParameters{
		sV.ownBK,
	}
	partialPubKeySlice := make([][]byte, 1)
	partialPubKeySlice[0] = sV.partialPubKey
	pubKeyByte := sV.pubKey
	var pubKey bls12381.G1Affine
	_, err := pubKey.SetBytes(pubKeyByte)
	if err != nil {
		return err
	}
	// check the correctness of the partial Point
	for i := 0; i < len(partialPubKeyMsg); i++ {
		tempPartialPubKey := partialPubKeyMsg[i].PartialPubKey
		// The length of a correct signature is 48
		if len(tempPartialPubKey) > G1MaxByteLength {
			return ErrFailureSign
		}
		partialPubKeySlice = append(partialPubKeySlice, tempPartialPubKey)
		tempBks, err := partialPubKeyMsg[i].Bk.ToBk(bls12381CurveOrder)
		if err != nil {
			return err
		}
		bkss = append(bkss, tempBks)
		getPubKey := partialPubKeyMsg[i].PublicKey
		if subtle.ConstantTimeCompare(pubKeyByte, getPubKey) != 1 {
			return ErrPubKeyDifferent
		}
		// check zk-proof
		proof := partialPubKeyMsg[i].Proof
		err = proof.Verify(tempPartialPubKey)
		if err != nil {
			return err
		}
	}
	bkCoefficient, err := bkss.ComputeBkCoefficient(sV.threshold, bls12381CurveOrder)
	if err != nil {
		return err
	}
	// Compute the public Key from share points
	var result bls12381.G1Affine
	_, err = result.SetBytes(partialPubKeySlice[0])
	if err != nil {
		return err
	}
	result.ScalarMultiplication(&result, bkCoefficient[0])
	for i := 1; i < len(partialPubKeySlice); i++ {
		var temp bls12381.G1Affine
		_, err = temp.SetBytes(partialPubKeySlice[i])
		if err != nil {
			return err
		}
		temp.ScalarMultiplication(&temp, bkCoefficient[i])
		result.Add(&result, &temp)
	}
	// check the same of result and pubKey
	if !pubKey.Equal(&result) {
		return ErrShareValidationFailure
	}
	return nil
}

func validationShareAndPubKey(share []byte, pubKey []byte) (*big.Int, *bls12381.G1Affine, error) {
	// check the correctness of share and pubKey
	bshare := new(big.Int).SetBytes(share)
	err := utils.InRange(bshare, big1, bls12381CurveOrder)
	if err != nil {
		return nil, nil, err
	}
	if len(pubKey) > G1MaxByteLength {
		return nil, nil, ErrWrongLengthPubKey
	}
	var pubKeyG1 bls12381.G1Affine
	_, err = pubKeyG1.SetBytes(pubKey)
	if err != nil {
		return nil, nil, err
	}
	return bshare, &pubKeyG1, nil
}

// ref : https://datatracker.ietf.org/doc/html/rfc8235
func NewG1SchnorrZkProof(secret *big.Int, pubKey []byte, auxMsg []byte) (*SchnorrProofG1Message, error) {
	v, err := utils.RandomPositiveInt(bls12381CurveOrder)
	if err != nil {
		return nil, err
	}
	var VPoint bls12381.G1Affine
	VPoint.ScalarMultiplicationBase(v)
	VPointByte := VPoint.Bytes()

	var G1 bls12381.G1Affine
	G1.ScalarMultiplicationBase(big1)
	G1Byte := G1.Bytes()
	// Compute c

	msgs := []proto.Message{&any.Any{
		Value: pubKey,
	}, &any.Any{
		Value: auxMsg,
	}, &any.Any{
		Value: G1Byte[:],
	}}

	c, salt, err := utils.HashProtosRejectSampling(bls12381CurveOrder, msgs...)
	if err != nil {
		return nil, err
	}
	r := new(big.Int).Mul(secret, c)
	r.Sub(v, r)
	r.Mod(r, bls12381CurveOrder)
	result := &SchnorrProofG1Message{
		Salt:   salt,
		V:      VPointByte[:],
		R:      r.Bytes(),
		AuxMsg: auxMsg,
	}
	err = result.Verify(pubKey)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (msg *SchnorrProofG1Message) Verify(pubKey []byte) error {
	VByte := msg.V
	var VPoint bls12381.G1Affine
	if len(VByte) > G1MaxByteLength {
		return ErrWrongLengthPubKey
	}
	_, err := VPoint.SetBytes(VByte)
	if err != nil {
		return err
	}
	if len(pubKey) > G1MaxByteLength {
		return ErrWrongLengthPubKey
	}
	var pubKeyG1 bls12381.G1Affine
	_, err = pubKeyG1.SetBytes(pubKey)
	if err != nil {
		return err
	}

	r := new(big.Int).SetBytes(msg.GetR())
	err = utils.InRange(r, big0, bls12381CurveOrder)
	if err != nil {
		return err 
	}

	salt := msg.Salt
	auxMsg := msg.AuxMsg

	var G1 bls12381.G1Affine
	G1.ScalarMultiplicationBase(big1)
	G1Byte := G1.Bytes()

	// Calculate c
	msgs := []proto.Message{&any.Any{
		Value: pubKey,
	}, &any.Any{
		Value: auxMsg,
	}, &any.Any{
		Value: G1Byte[:],
	}}

	c, err := utils.HashProtosToInt(salt, msgs...)
	if err != nil {
		return err
	}
	err = utils.InRange(c, big1, bls12381CurveOrder)
	if err != nil {
		return err
	}
	// Calculate V = r*G + pubKey*c
	var checkPoint, AcPoint bls12381.G1Affine
	checkPoint.ScalarMultiplicationBase(r)
	AcPoint.ScalarMultiplication(&pubKeyG1, c)
	checkPoint.Add(&checkPoint, &AcPoint)
	if !VPoint.Equal(&checkPoint) {
		return ErrSchnorrFailure
	}
	return nil
}
