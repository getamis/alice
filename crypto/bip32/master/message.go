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

package master

import (
	"github.com/getamis/alice/types"
)

func (m *Message) IsValid() bool {
	switch m.Type {
	case Type_Initial:
		return m.GetInitial() != nil
	case Type_OtReceiver:
		return m.GetOtReceiver() != nil
	case Type_OtSendResponse:
		return m.GetOtSendResponse() != nil
	case Type_Commitment:
		return m.GetCommitment() != nil
	case Type_Decommitment:
		return m.GetDecommitment() != nil
	case Type_Result:
		return m.GetResult() != nil
	case Type_Verify:
		return m.GetVerify() != nil
	}
	return false
}

func (m *Message) GetMessageType() types.MessageType {
	return types.MessageType(m.Type)
}
