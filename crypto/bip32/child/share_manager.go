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

package child

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
)

const (
	// MinHardenKey is the firsrt index of "harded" child key in the bip32 spec
	MinHardenKey = uint32(0x80000000)

	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33
)

var (
	big2 = big.NewInt(2)

	// ErrNonHardenedKey is returned the index < MinHardenKey
	ErrNonHardenedKey = errors.New("the index can not produce any hardened key")
	// ErrHardenedKey is returned the index >= MinHardenKey
	ErrHardenedKey = errors.New("the index can not produce any nonhardened key")
	// ErrNotCorrectShare is the share value is invalid
	ErrNotCorrectShare = errors.New("the share value is invalid")
)

/*
	This BIP-32 Library just for the use of TSS.
	Warn: This Library does not check the condition:
	In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i.
	(Note: this has probability lower than 1 in 2^127)
	Therefore, it maybe product "Invalid" the child key.
*/

// TODO: consider replace shareSimply to the original share + bk coefficeints
type shareManager struct {
	share     *big.Int
	publicKey *ecpointgrouplaw.ECPoint
	// 32 bytes
	chainCode []byte
	depth     byte
}

func NewShareManager(share *big.Int, pubKey *ecpointgrouplaw.ECPoint, chainCode []byte, depth byte) (*shareManager, error) {
	n := pubKey.GetCurve().Params().N
	if n.Cmp(share) < 1 {
		return nil, ErrNotCorrectShare
	}
	return &shareManager{
		share:     share,
		publicKey: pubKey,
		chainCode: chainCode,
		depth:     depth,
	}, nil
}

func (sHolder *shareManager) newHmacSha512() *hmacSHA512 {
	return NewHmacSha512(sHolder.chainCode)
}

func (sHolder *shareManager) ComputeHardenKeyPrepareData() ([]uint64, error) {
	return sHolder.newHmacSha512().ComputeFirstBlockHash()
}

// new Translate (should remainder) and childeShare
func (sHolder *shareManager) ComputeHardenedChildShare(childIndex uint32, secondState []byte) (*big.Int, *shareManager, error) {
	if childIndex < MinHardenKey {
		return nil, nil, ErrNonHardenedKey
	}
	curve := sHolder.publicKey.GetCurve()
	curveN := curve.Params().N
	hashResult := sHolder.newHmacSha512().Digest(secondState)
	translate := new(big.Int).Mod(new(big.Int).SetBytes(hashResult[0:32]), curveN)

	// Because now we have two people, so we modify this value such such that s1+1/.2*translate + s2 + 1/2*translate = privatekey
	halfTranslate := new(big.Int).ModInverse(big2, curveN)
	halfTranslate.Mul(halfTranslate, translate)
	halfTranslate.Mod(halfTranslate, curveN)
	childPubKey := ecpointgrouplaw.ScalarBaseMult(curve, translate)
	childPubKey, err := sHolder.publicKey.Add(childPubKey)
	if err != nil {
		return nil, nil, err
	}

	childShare := new(big.Int).Add(sHolder.share, halfTranslate)
	childShare = childShare.Mod(childShare, curveN)
	return translate, &shareManager{
		share:     childShare,
		chainCode: hashResult[32:],
		depth:     sHolder.depth + 1,
		publicKey: childPubKey,
	}, nil
}

func (sHolder *shareManager) ComputeNonHardenedChildShare(childIndex uint32) (*shareManager, error) {
	if childIndex >= MinHardenKey {
		return nil, ErrHardenedKey
	}
	childIndexBytes := uint32Bytes(childIndex)
	data := compressPublicKey(sHolder.publicKey)
	data = append(data, childIndexBytes...)

	hmac := hmac.New(sha512.New, sHolder.chainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	hashResult := hmac.Sum(nil)
	translate := new(big.Int).SetBytes(hashResult[0:32])
	childShare := new(big.Int).Add(sHolder.share, translate)
	childShare = childShare.Mod(childShare, sHolder.publicKey.GetCurve().Params().N)
	return &shareManager{
		// TODO: Child pub key?
		share:     childShare,
		chainCode: hashResult[32:],
		depth:     sHolder.depth + 1,
	}, nil
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

func compressPublicKey(pubKey *ecpointgrouplaw.ECPoint) []byte {
	var key bytes.Buffer
	x := pubKey.GetX()
	y := pubKey.GetY()
	// Write header; 0x2 for even y value; 0x3 for odd
	key.WriteByte(byte(0x2) + byte(y.Bit(0)))

	// Write X coord; Pad the key so x is aligned with the LSB. Pad size is key length - header size (1) - xBytes size
	xBytes := x.Bytes()
	for i := 0; i < (PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)
	return key.Bytes()
}
