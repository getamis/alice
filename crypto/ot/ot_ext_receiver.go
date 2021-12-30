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

package ot

import (
	"github.com/aisuosuo/alice/crypto/binaryfield"
	"github.com/aisuosuo/alice/crypto/utils"
)

/*
	We implement OT protocol in Fig 5: Blazing Fast OT for Three-round UC OT Extension
*/

type OtExtReceiver struct {
	otSend *OtSender

	sid []byte
	u   []*binaryfield.FieldElement
	v   []*binaryfield.FieldElement
	M   [][]byte // 0, 1 matrix
	R   [][]byte
	D   [][]byte
	r   []byte
	msg *OtExtReceiveMessage
}

// Note: r is the bit expression
func NewExtReceiver(sid []byte, r []byte, otRMsg *OtReceiverMessage) (*OtExtReceiver, error) {
	m := uint(len(r))
	otSend, err := NewSender(sid, otRMsg)
	if err != nil {
		return nil, err
	}
	kappa := uint(len(otRMsg.GetBi()))
	// bitLength to byteLength
	outputByteLength := int(m+kappa) >> 3
	M, err := getMatrixM(sid, otSend.p0, outputByteLength)
	if err != nil {
		return nil, err
	}
	R, err := getMatrixR(kappa, otSend.p0, r, outputByteLength)
	if err != nil {
		return nil, err
	}
	D, err := getMatrixD(sid, otSend.p1, M, R, outputByteLength)
	if err != nil {
		return nil, err
	}

	chi, err := hashRO2(sid, D)
	if err != nil {
		return nil, err
	}
	u, v, err := computeUandV(chi, M, R)
	if err != nil {
		return nil, err
	}
	uMsg := binaryfield.TransFieldElementMsg(u)
	vMsg := binaryfield.TransFieldElementMsg(v)
	return &OtExtReceiver{
		sid:    sid,
		otSend: otSend,
		u:      u,
		v:      v,
		M:      M,
		R:      R,
		D:      D,
		r:      r,
		msg: &OtExtReceiveMessage{
			OtSendMsg: otSend.GetOtSenderMessage(),
			D:         D,
			U:         uMsg,
			V:         vMsg,
		},
	}, nil
}

func (otextRec *OtExtReceiver) GetOtExtReceiveMessage() *OtExtReceiveMessage {
	return otextRec.msg
}

func (otextRec *OtExtReceiver) GetOTFinalResult(otextSendMsg *OtExtSendResponseMessage) ([][]byte, error) {
	err := otextRec.otSend.Verify(otextSendMsg.OtRecVerifyMsg)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, len(otextRec.r))
	for i := 0; i < len(result); i++ {
		crfResult, err := crf(otextRec.sid, i, getRow(i, otextRec.M))
		if err != nil {
			return nil, err
		}
		if otextRec.r[i] == 0 {
			result[i] = utils.Xor(crfResult, otextSendMsg.A0[i])
			continue
		}
		result[i] = utils.Xor(crfResult, otextSendMsg.A1[i])
	}
	return result, nil
}
