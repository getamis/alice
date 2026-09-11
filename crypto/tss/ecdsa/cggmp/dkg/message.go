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

func (m *Message) NewEchoHashRelay(hash []byte) types.Message {
	return &Message{
		Type: m.Type,
		Id:   m.Id,
		Body: &Message_EchoHashRelay{EchoHashRelay: hash},
	}
}

func (m *Message) GetEchoMessage() types.Message {
	switch m.Type {
	case Type_Peer:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Peer{
				Peer: &BodyPeer{
					Bk:         m.GetPeer().GetBk(),
					Commitment: m.GetPeer().GetCommitment(),
				},
			},
		}
	case Type_Decommit:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Decommit{
				Decommit: &BodyDecommit{
					HashDecommitment: m.GetDecommit().GetHashDecommitment(),
					PointCommitment:  m.GetDecommit().GetPointCommitment(),
				},
			},
		}
	case Type_Result:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Result{
				Result: &BodyResult{
					SiGProofMsg: m.GetResult().GetSiGProofMsg(),
				},
			},
		}
	}
	return nil
}
