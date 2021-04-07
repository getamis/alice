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

package verifier

import (
	"github.com/getamis/alice/crypto/tss/message/types"
)

func (m *Message) IsValid() bool {
	switch m.Type {
	case Type_MsgUser0:
		return m.GetUser0() != nil
	case Type_MsgUser1:
		return m.GetUser1() != nil
	case Type_MsgServer0:
		return m.GetServer0() != nil
	}
	return false
}

func (m *Message) GetMessageType() types.MessageType {
	return types.MessageType(m.Type)
}

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}
