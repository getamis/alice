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
	"errors"

	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/utils"
	bls12381 "github.com/kilic/bls12-381"
)

const (
	// maxRetry defines the max retries to generate proof
	maxRetry = 100
)

var (
	domain    = []byte("BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN")
	blsEngine = bls12381.NewEngine()
	g1        = bls12381.NewG1()
	g2        = bls12381.NewG2()
	big0      = big.NewInt(0)

	//ErrTrivialPubKey is returned if the pubKey is trivial
	ErrTrivialPubKey = errors.New("Trivial Pubkey")
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
	//ErrSmallThreshold is returned if the threshold is small than total people.
	ErrSmallThreshold = errors.New("the threshold is small than total people")
	//ErrThresholdOne is returned if the threshold is 1.
	ErrThresholdOne = errors.New("the threshold is 1")
)

// ECPoint is the struct for an elliptic curve point.
type Participant struct {
	threshold uint32
	message   []byte
	share     *big.Int
	bk        *birkhoffinterpolation.BkParameter

	allbks birkhoffinterpolation.BkParameters

	messagePoint *bls12381.PointG2
	pubKey       *bls12381.PointG1
}

// TODO: What is domain?
func (par *Participant) Sign() (*bls12381.PointG2, error) {
	signPoint, err := bls12381.NewG2().MapToCurve(par.message)
	par.messagePoint = signPoint
	if err != nil {
		return nil, err
	}
	allbkCoeff, err := par.allbks.ComputeBkCoefficient(par.threshold, g1.Q())
	allBkCoefficient := make(map[*big.Int]*big.Int)
	for i := 0; i < len(par.allbks); i++ {
		x := par.allbks[i].GetX()
		allBkCoefficient[x] = allbkCoeff[i]
	}
	bkShare := new(big.Int).Mul(allBkCoefficient[par.bk.GetX()], par.share)
	bkShare.Mod(bkShare, g1.Q())
	R := g2.MulScalarBig(blsEngine.G2.New(), signPoint, new(big.Int).Mul(allBkCoefficient[par.bk.GetX()], par.share))
	// g2.ToCompressed(R)
	return R, nil
}

// Or Aggregator
func computeSignature(partialSignature []*bls12381.PointG2) (*bls12381.PointG2, error) {
	result := blsEngine.G2.New().Zero()
	for i := 0; i < len(partialSignature); i++ {
		if !g2.IsOnCurve(partialSignature[i]) {
			return nil, ErrVerifyFailure
		}
		result = g2.Add(result, result, partialSignature[i])
	}
	return result, nil
}

// Or Aggregator
func verifySignature(sig *bls12381.PointG2, pubkey *bls12381.PointG1, msg *bls12381.PointG2) error {
	if !g2.IsOnCurve(sig) {
		return ErrVerifyFailure
	}
	C1 := blsEngine.Reset().AddPair(pubkey, msg)
	result1 := C1.Result()
	C2 := blsEngine.Reset().AddPair(blsEngine.G1.One(), sig)
	result2 := C2.Result()
	if !result1.Equal(result2) {
		return ErrVerifyFailure
	}
	return nil
}

func (par *Participant) GetSignature(partialSignature []*bls12381.PointG2) (*bls12381.PointG2, error) {
	result, err := computeSignature(partialSignature)
	if err != nil {
		return nil, err
	}
	err = verifySignature(result, par.pubKey, par.messagePoint)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func verifyPubKey(pubKey *bls12381.PointG1) error {
	if g1.IsZero(pubKey) {
		return ErrTrivialPubKey
	}
	if !g1.IsOnCurve(pubKey) {
		return ErrTrivialPubKey
	}
	return nil
}

func NewParticipant(threshold uint32, message []byte, share *big.Int, pubKey *bls12381.PointG1, ownbk *birkhoffinterpolation.BkParameter, allbks birkhoffinterpolation.BkParameters) (*Participant, error) {
	if threshold == 1 {
		return nil, ErrThresholdOne
	}
	if threshold > uint32(len(allbks)) {
		return nil, ErrSmallThreshold
	}
	err := utils.InRange(share, big0, g1.Q())
	if err != nil {
		return nil, err
	}
	err = verifyPubKey(pubKey)
	if err != nil {
		return nil, err
	}
	return &Participant{
		threshold: threshold,
		message:   message,
		share:     share,
		bk:        ownbk,
		allbks:    allbks,
		pubKey:    pubKey,
	}, nil
}
