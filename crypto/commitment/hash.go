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
	"github.com/golang/protobuf/ptypes/any"
)

// Note: So far, the family of SHA3(i.e. including black2) can protect against length extension attacks.
var (
	// ErrDifferentDigest is returned if the two digests are different.
	ErrDifferentDigest = errors.New("different digests")
)

type HashCommitmenter struct {
	digest []byte
	data   []byte
	salt   []byte
}

func NewProtoHashCommitmenter(msg proto.Message) (*HashCommitmenter, error) {
	agMsgBs, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return NewHashCommitmenter(agMsgBs)
}

func NewHashCommitmenter(data []byte) (*HashCommitmenter, error) {
	salt, err := utils.GenRandomBytes(utils.SaltSize)
	if err != nil {
		return nil, err
	}
	digest, err := getDigest(salt, data)
	if err != nil {
		return nil, err
	}
	return &HashCommitmenter{
		digest: digest,
		data:   data,
		salt:   salt,
	}, nil
}

func (c *HashCommitmenter) GetCommitmentMessage() *HashCommitmentMessage {
	return &HashCommitmentMessage{
		Digest: c.digest,
	}
}

func (c *HashCommitmenter) GetDecommitmentMessage() *HashDecommitmentMessage {
	return &HashDecommitmentMessage{
		Data: c.data,
		Salt: c.salt,
	}
}

func (c *HashCommitmentMessage) Decommit(msg *HashDecommitmentMessage) error {
	digest, err := getDigest(msg.Salt, msg.Data)
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
func getDigest(salt []byte, originData []byte) ([]byte, error) {
	return utils.HashProtos(salt, &any.Any{
		Value: originData,
	})
}
