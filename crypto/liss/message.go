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

package liss

import (
	"math/big"

	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/internal/message/types"
)

func (m *Message) IsValid() bool {
	switch m.Type {
	case Type_BqCommitment:
		return m.GetBqCommitment() != nil
	case Type_BqDecommitment:
		return m.GetBqDedemmitment() != nil
	}
	return false
}

func (m *Message) GetMessageType() types.MessageType {
	return types.MessageType(m.Type)
}

func (msg *BqDecommit) verify(commitment []byte) error {
	result, err := utils.HashProtosToInt(msg.Salt, msg.GetBqform())
	if err != nil {
		return err
	}

	if result.Cmp(new(big.Int).SetBytes(commitment)) != 0 {
		return ErrFailedVerify
	}

	return nil
}
