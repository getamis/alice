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

package sign

import (
	"github.com/getamis/alice/types"
)

func (m *Message) IsValid() bool {
	switch m.Type {
	case Type_Round1:
		return m.GetRound1() != nil
	case Type_Round2:
		return m.GetRound2() != nil
	case Type_Round3:
		return m.GetRound3() != nil
	case Type_Round4:
		return m.GetRound4() != nil
	case Type_Err1:
		return m.GetErr1() != nil
	case Type_Err2:
		return m.GetErr2() != nil
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
	case Type_Round1:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round1{
				Round1: &Round1Msg{
					KCiphertext:     m.GetRound1().GetKCiphertext(),
					GammaCiphertext: m.GetRound1().GetGammaCiphertext(),
					// Not broadcast to all in echo protocol
					// Psi:             m.GetRound1().GetPsi(),
				},
			},
		}
	case Type_Round2:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round2{
				Round2: &Round2Msg{
					Gamma: m.GetRound2().GetGamma(),
				},
			},
		}
	case Type_Round3:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round3{
				Round3: &Round3Msg{
					Delta:    m.GetRound3().GetDelta(),
					BigDelta: m.GetRound3().GetBigDelta(),
				},
			},
		}
	case Type_Round4:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round4{
				Round4: &Round4Msg{
					Sigmai: m.GetRound4().GetSigmai(),
				},
			},
		}
	}
	return nil
}
