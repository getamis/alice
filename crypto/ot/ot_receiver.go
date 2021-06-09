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
	"crypto/subtle"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/ptypes/any"
)

/*
	We implement OT protocol in Fig 8: Blazing Fast OT for Three-round UC OT Extension
*/

type OtReceiver struct {
	sid  []byte
	seed []byte
	a    []*big.Int
	b    []uint8
	msg  *OtReceiverMessage
}

// Receiver message:
func NewReceiver(sid []byte, kappa int, ell int) (*OtReceiver, error) {
	seed, err := utils.GenRandomBytes(kappa >> 3)
	if err != nil {
		return nil, err
	}
	T, err := generateT(sid, seed)
	if err != nil {
		return nil, err
	}

	// Randonly choose bi, alphai in Z_q and set Bi := alphai*G+bi*T.
	bimsg := make([]*pt.EcPointMessage, ell)
	b := make([]uint8, ell)
	a := make([]*big.Int, ell)
	for i := 0; i < ell; i++ {
		bi, err := utils.RandomInt(big2)
		if err != nil {
			return nil, err
		}
		alphai, err := utils.RandomInt(fieldOrder)
		if err != nil {
			return nil, err
		}
		Bi := pt.ScalarBaseMult(T.GetCurve(), alphai)
		if bi.Cmp(big0) > 0 {
			Bi, err = Bi.Add(T)
			if err != nil {
				return nil, err
			}
		}
		tempMsg, err := Bi.ToEcPointMessage()
		if err != nil {
			return nil, err
		}
		bimsg[i] = tempMsg
		b[i] = uint8(bi.Uint64())
		a[i] = alphai
	}
	return &OtReceiver{
		sid:  sid,
		seed: seed,
		a:    a,
		b:    b,
		msg: &OtReceiverMessage{
			Seed: seed,
			Bi:   bimsg,
		},
	}, nil
}

func (o *OtReceiver) GetReceiverMessage() *OtReceiverMessage {
	return o.msg
}

func (otR *OtReceiver) Response(otSenderMsg *OtSenderMessage) (*OtReceiverVerifyMessage, [][]byte, error) {
	z, err := otSenderMsg.GetZ().ToPoint()
	if err != nil {
		return nil, nil, err
	}
	lens := len(otR.a)
	resp := make([][]byte, lens)
	pib := make([][]byte, lens)
	for i := 0; i < lens; i++ {
		zalphai := z.ScalarMult(otR.a[i])
		zalphaiMSg, err := zalphai.ToEcPointMessage()
		if err != nil {
			return nil, nil, err
		}
		// compute pibi := RO2(sid, z^alphai)
		pib[i], err = utils.HashProtos(otR.sid, zalphaiMSg)
		if err != nil {
			return nil, nil, err
		}
		resi, err := ro3(otR.sid, pib[i])
		if err != nil {
			return nil, nil, err
		}
		bchalli := utils.BinaryMul(otR.b[i], otSenderMsg.GetChall()[i])
		resp[i] = utils.Xor(resi, bchalli)
	}
	challMSg := &OtChallengeMessage{
		Challenge: resp,
	}
	anspai, err := utils.HashProtos(otR.sid, challMSg)
	if err != nil {
		return nil, nil, err
	}
	gammagot, err := utils.HashProtos(otR.sid, &any.Any{
		Value: anspai,
	})
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(gammagot, otSenderMsg.GetGamma()) != 1 {
		return nil, nil, ErrFailedVerify
	}
	return &OtReceiverVerifyMessage{
		Ans: anspai,
	}, pib, nil
}
