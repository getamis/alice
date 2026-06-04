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

package cggmp

import (
	"encoding/binary"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/types"
	"google.golang.org/protobuf/proto"
)

func ComputeSSID(sid, id, rid []byte) []byte {
	totalLen := 4 + len(sid) + 4 + len(id) + 4 + len(rid)
	result := make([]byte, 0, totalLen)
	appendWithLength := func(data []byte) {
		lengthBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
		result = append(result, lengthBuf...)
		result = append(result, data...)
	}

	appendWithLength(sid)
	appendWithLength(id)
	appendWithLength(rid)

	return result
}

func ComputeZKSsid(ssid []byte, bk *birkhoffinterpolation.BkParameter, fieldOrder *big.Int) []byte {
	separation := []byte(",")
	result := make([]byte, len(ssid))
	copy(result, ssid)
	result = append(result, separation...)
	byteLen := (fieldOrder.BitLen() + 7) / 8
	xBytes := make([]byte, byteLen)
	bk.GetX().FillBytes(xBytes)
	return append(xBytes, result...)
}

func Broadcast(pm types.PeerManager, msg proto.Message) {
	for _, id := range pm.PeerIDs() {
		pm.MustSend(id, msg)
	}
}
