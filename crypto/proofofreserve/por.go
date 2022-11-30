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
	"errors"

	"math/big"

	bulletproof "github.com/getamis/alice/crypto/proofofreserve/bulletproof"
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	bls12381 "github.com/kilic/bls12-381"
)

const (
	// SaltSize is based on blake2b256
	SaltSize = 32
	// maxGenHashValue defines the max retries to generate hash value by reject sampling
	maxGenNHashValue = 100
)

var (
	DST_G1    = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
	DST_G2    = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	blsEngine = bls12381.NewEngine()
	g1        = bls12381.NewG1()
	g2        = bls12381.NewG2()
	big0      = big.NewInt(0)
	big1      = big.NewInt(1)
	// Base Point
	G1 = blsEngine.G1.One()
	G2 = blsEngine.G2.One()

	//ErrTrivialPubKey is returned if the pubKey is trivial
	ErrTrivialPubKey = errors.New("Trivial Pubkey")
	//ErrUserReserveTooLarge is returned if user's reserve is too large.
	ErrUserReserveTooLarge = errors.New("user's reserve is too large")
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
)

type PubKey struct {
	H *bls12381.PointG2
	G *bls12381.PointG2

	bulletPubParameter *bulletproof.PublicParameter
}

type userCommitmentInfo struct {
	salt       []byte
	commitment *bls12381.PointG2
}

type ProofOfReserveCommitment struct {
	C            *bls12381.PointG2
	TotalReserve *big.Int
	omega        *bls12381.PointG1
	userInfo     map[string]*userCommitmentInfo
	userProof    map[string]*bulletproof.ProverMessage
}

func GenerateCommitmentPubKey(message []byte, rangeProofBinarySize uint) (*PubKey, error) {
	H, err := g2.HashToCurve(message, DST_G1)
	if err != nil {
		return nil, err
	}
	G := blsEngine.G2.One()
	if g2.Equal(H, G) {
		return nil, ErrTrivialPubKey
	}

	rangeProofPubParameter, err := bulletproof.NewPublicParameter(G, H, rangeProofBinarySize)
	if err != nil {
		return nil, err
	}
	return &PubKey{
		H:                  H,
		G:                  G,
		bulletPubParameter: rangeProofPubParameter,
	}, nil
}

func (pub *PubKey) computeSingleUserCommitment(idInfo, reserve *big.Int) *bls12381.PointG2 {
	result := g2.MulScalarBig(blsEngine.G2.New(), pub.H, idInfo)
	reserveG := g2.MulScalarBig(blsEngine.G2.New(), pub.G, reserve)
	result = g2.Add(result, reserveG, result)
	return result
}

func computeIDInfo(salt []byte, msgs ...proto.Message) (*big.Int, error) {
	idInfo, err := utils.HashProtosToInt(salt, msgs...)
	if err != nil {
		return nil, err
	}
	return idInfo, nil
}

// compute: Hash(salt, ID)*H+reserve*G
func (pub *PubKey) computeUserCommitment(ID string, reserve *big.Int) (*userCommitmentInfo, *big.Int, error) {
	// note : the order of g2 is 52435875175126190479447740508185965837690552500527637822603658699938581184513 < 2^255
	g2Order := g2.Q()
	idMsg := &any.Any{
		Value: []byte(ID),
	}
	idInfo, salt, err := utils.HashProtosRejectSampling(g2Order, idMsg)
	if err != nil {
		return nil, nil, err
	}
	result := pub.computeSingleUserCommitment(idInfo, reserve)
	return &userCommitmentInfo{
		salt:       salt,
		commitment: result,
	}, idInfo, nil
}

func (pub *PubKey) GenerateCommitmentData(userInfo map[string]*big.Int) (*ProofOfReserveCommitment, error) {
	g2Order := g2.Q()
	omegaValue := big.NewInt(0)
	totalReserve := big.NewInt(0)
	userCommitMap := make(map[string]*userCommitmentInfo)
	userBulletProof := make(map[string]*bulletproof.ProverMessage)
	C := blsEngine.G2.New()
	for id, v := range userInfo {
		tempUserInfo, tempidInfo, err := pub.computeUserCommitment(id, v)
		if err != nil {
			return nil, err
		}

		C = g2.Add(C, C, tempUserInfo.commitment)
		userCommitMap[id] = tempUserInfo
		omegaValue.Add(omegaValue, tempidInfo)
		omegaValue.Mod(omegaValue, g2Order)
		totalReserve.Add(totalReserve, v)
		bullerProver := bulletproof.NewProver(pub.bulletPubParameter, v, tempidInfo, tempUserInfo.commitment)
		tempProof, err := bullerProver.InitialProveData()
		if err != nil {
			return nil, err
		}

		userBulletProof[id] = tempProof
	}
	// Compute all commitment
	modReserve := new(big.Int).Mod(totalReserve, g2Order)
	if modReserve.Cmp(totalReserve) != 0 {
		return nil, ErrUserReserveTooLarge
	}
	omega := g1.MulScalarBig(blsEngine.G1.New(), G1, omegaValue)

	// check all Data:
	result := &ProofOfReserveCommitment{
		C:            C,
		omega:        omega,
		TotalReserve: totalReserve,
		userInfo:     userCommitMap,
		userProof:    userBulletProof,
	}
	err := pub.VerifyTotalReserve(result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (userInfo *userCommitmentInfo) userVerifyOwnCommitment(id string, reserve *big.Int, pub *PubKey, msg *bulletproof.ProverMessage) error {
	g2Order := g2.Q()
	// for accelerating reject sampling, we adjust idInfo because idInfo < 2^255.
	idInfo, err := computeIDInfo(userInfo.salt, &any.Any{
		Value: []byte(id),
	})
	if err != nil {
		return err
	}
	if idInfo.Cmp(g2Order) > -1 {
		return ErrVerifyFailure
	}
	if !g2.Equal(pub.computeSingleUserCommitment(idInfo, reserve), userInfo.commitment) {
		return ErrVerifyFailure
	}
	// TODO: check all range Proof
	err = msg.Verify(pub.bulletPubParameter, userInfo.commitment)
	if err != nil {
		return err
	}
	return nil
}

func (pub *PubKey) VerifyTotalReserve(porCommitment *ProofOfReserveCommitment) error {
	C := blsEngine.G2.New()
	totalNuberOfUser := uint64(0)
	for _, v := range porCommitment.userInfo {
		C = g2.Add(C, C, v.commitment)
		totalNuberOfUser++
	}
	if !g2.Equal(C, porCommitment.C) {
		return ErrVerifyFailure
	}
	C1 := blsEngine.AddPair(G1, porCommitment.C)
	result1 := C1.Result()
	C2 := blsEngine.AddPair(porCommitment.omega, pub.H)

	reservePoint := g2.MulScalarBig(blsEngine.G2.New(), G2, porCommitment.TotalReserve)
	C2.AddPair(blsEngine.G1.One(), reservePoint)
	result2 := C2.Result()
	if !result1.Equal(result2) {
		return ErrVerifyFailure
	}
	blsEngine = blsEngine.Reset()
	compare := new(big.Int).SetUint64(totalNuberOfUser)
	compare.Mul(compare, pub.bulletPubParameter.UpperBoundOfRange)
	if compare.Cmp(g2.Q()) != -1 {
		return ErrUserReserveTooLarge
	}
	return nil
}
