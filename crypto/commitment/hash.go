// Copyright © 2020 AMIS Technologies
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

package commitment

import (
	"crypto/subtle"
	"errors"

	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/blake2b"
)

// Note: So far, the family of SHA3(i.e. including black2) can protect against length extension attacks.
var (
	// ErrDifferentDigest is returned if the two digests are different.
	ErrDifferentDigest = errors.New("different digests")
)

type HashCommitmenter struct {
	blake2bKey []byte
	digest     []byte
	data       []byte
	salt       []byte
}

func NewProtoHashCommitmenter(msg proto.Message, minSaltSize int) (*HashCommitmenter, error) {
	agMsgBs, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return NewHashCommitmenter(agMsgBs, minSaltSize)
}

func NewHashCommitmenter(data []byte, minSaltSize int) (*HashCommitmenter, error) {
	lens := len(data)
	if lens < minSaltSize {
		lens = minSaltSize
	}
	randomSalt, err := utils.GenRandomBytes(lens)
	if err != nil {
		return nil, err
	}
	blake2bKey, err := utils.GenRandomBytes(blake2b.Size256)
	if err != nil {
		return nil, err
	}
	digest, err := getDigest(blake2bKey, data, randomSalt)
	if err != nil {
		return nil, err
	}
	return &HashCommitmenter{
		blake2bKey: blake2bKey,
		digest:     digest,
		data:       data,
		salt:       randomSalt,
	}, nil
}

func (c *HashCommitmenter) GetCommitmentMessage() *HashCommitmentMessage {
	return &HashCommitmentMessage{
		Blake2BKey: c.blake2bKey,
		Digest:     c.digest,
	}
}

func (c *HashCommitmenter) GetDecommitmentMessage() *HashDecommitmentMessage {
	return &HashDecommitmentMessage{
		Data: c.data,
		Salt: c.salt,
	}
}

func (c *HashCommitmentMessage) Decommit(msg *HashDecommitmentMessage) error {
	digest, err := getDigest(c.Blake2BKey, msg.Data, msg.Salt)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, c.Digest) != 1 {
		return ErrDifferentDigest
	}
	return nil
}

func (c *HashCommitmentMessage) DecommitToProto(msg *HashDecommitmentMessage, proroMsg proto.Message) error {
	err := c.Decommit(msg)
	if err != nil {
		return err
	}
	err = proto.Unmarshal(msg.Data, proroMsg)
	if err != nil {
		return err
	}
	return nil
}
func getDigest(blake2bKey []byte, originData []byte, salt []byte) ([]byte, error) {
	blake2b256, err := blake2b.New256(blake2bKey)
	if err != nil {
		return nil, err
	}
	checkData := append(originData, salt...)
	digest := blake2b256.Sum(checkData)
	return digest, nil
}
