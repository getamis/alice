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

package signSix

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
	case Type_Round5:
		return m.GetRound5() != nil
	case Type_Round6:
		return m.GetRound6() != nil
	case Type_Round7:
		return m.GetRound7() != nil
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
					Z1:              m.GetRound1().GetZ1(),
					Z2:              m.GetRound1().GetZ2(),
					// Not broadcast to all in echo protocol
					// Psi:             m.GetRound1().GetPsi(),
				},
			},
		}
	case Type_Round3:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round3{
				Round3: &Round3Msg{
					Delta: m.GetRound3().GetDelta(),
					Z1Hat: m.GetRound3().GetZ1Hat(),
					Z2Hat: m.GetRound3().GetZ2Hat(),
				},
			},
		}
	case Type_Round4:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round4{
				Round4: &Round4Msg{
					Gamma: m.GetRound4().GetGamma(),
				},
			},
		}
	case Type_Round5:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round5{
				Round5: &Round5Msg{
					Delta: m.GetRound5().GetDelta(),
				},
			},
		}
	case Type_Round6:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round6{
				Round6: &Round6Msg{
					S: m.GetRound6().GetS(),
				},
			},
		}
	case Type_Round7:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Body: &Message_Round7{
				Round7: &Round7Msg{
					Sigma: m.GetRound7().GetSigma(),
				},
			},
		}
	}
	return nil
}
