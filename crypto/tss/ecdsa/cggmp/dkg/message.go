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

package dkg

import (
	"github.com/getamis/alice/types"
	"github.com/minio/blake2b-simd"
	"google.golang.org/protobuf/proto"
)

func (m *Message) IsValid() bool {
	switch m.Type {
	case Type_Peer:
		return m.GetPeer() != nil
	case Type_Decommit:
		return m.GetDecommit() != nil
	case Type_Verify:
		return m.GetVerify() != nil
	case Type_Result:
		return m.GetResult() != nil
	}
	return false
}

func (m *Message) GetMessageType() types.MessageType {
	return types.MessageType(m.Type)
}

func (m *Message) Hash() ([]byte, error) {
	// NOTE: there's an issue if there's a map field in the message
	// https://developers.google.com/protocol-buffers/docs/encoding#implications
	// Deterministic serialization only guarantees the same byte output for a particular binary.
	bs, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	got := blake2b.Sum256(bs)
	return got[:], nil
}
