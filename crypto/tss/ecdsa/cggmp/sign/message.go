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
	"github.com/minio/blake2b-simd"
	"google.golang.org/protobuf/proto"
)

const echoHashSize = 32

func (m *Message) IsValid() bool {
	if m.GetEcho() {
		return len(m.GetEchoHash()) == echoHashSize && m.GetBody() == nil
	}

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

func (m *Message) IsEchoRelay() bool {
	return m.GetEcho()
}

func (m *Message) GetEchoMessage() types.Message {
	if m.GetEcho() {
		if !m.IsValid() {
			return nil
		}
		return m
	}

	hash, err := m.CalculateEchoHash()
	if err != nil || hash == nil {
		return nil
	}
	return &Message{Type: m.Type, Id: m.Id, Echo: true, EchoHash: hash}
}

func (m *Message) CalculateEchoHash() ([]byte, error) {
	echoPayload := m.getEchoPayload()
	if echoPayload == nil {
		return nil, nil
	}
	bs, err := proto.MarshalOptions{Deterministic: true}.Marshal(echoPayload)
	if err != nil {
		return nil, err
	}
	got := blake2b.Sum256(bs)
	return got[:], nil
}

func (m *Message) getEchoPayload() *Message {
	switch m.Type {
	case Type_Round1:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Echo: true,
			Body: &Message_Round1{
				Round1: &Round1Msg{
					KCiphertext:     m.GetRound1().GetKCiphertext(),
					GammaCiphertext: m.GetRound1().GetGammaCiphertext(),
				},
			},
		}
	case Type_Round2:
		return &Message{
			Type: m.Type,
			Id:   m.Id,
			Echo: true,
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
			Echo: true,
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
			Echo: true,
			Body: &Message_Round4{
				Round4: &Round4Msg{
					Sigmai: m.GetRound4().GetSigmai(),
				},
			},
		}
	}
	return nil
}
