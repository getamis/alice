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
	"errors"
	"math/big"
	"strconv"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/oprf/hasher"
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/ptypes/any"
)

const (
	asciiComma = 44
)

var (
	secp256k1Hasher = hasher.NewSECP256k1()
	fieldOrder      = secp256k1Hasher.GetN()
	big0            = big.NewInt(0)
	big1            = big.NewInt(1)
	big2            = big.NewInt(2)

	// ErrFailedVerify is returned if it's failed to verify
	ErrFailedVerify = errors.New("failed to verify")
	// ErrWrongInput is returned if the input is wrong
	ErrWrongInput = errors.New("wrong input")
)

/*
	We implement OT protocol in Fig 8: Blazing Fast OT for Three-round UC OT Extension
*/

type OtSender struct {
	ans []byte
	p0  [][]byte
	p1  [][]byte

	msg *OtSenderMessage
}

func NewSender(sid []byte, otReceiverMsg *OtReceiverMessage) (*OtSender, error) {
	T, err := generateT(sid, otReceiverMsg.GetSeed())
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomInt(fieldOrder)
	if err != nil {
		return nil, err
	}

	// z = r*G
	biArray := otReceiverMsg.GetBi()
	ell := len(biArray)
	z := pt.ScalarBaseMult(T.GetCurve(), r)
	p0 := make([][]byte, ell)
	p0Ro3 := make([][]byte, ell)
	p1 := make([][]byte, ell)
	chall := make([][]byte, ell)
	for i := 0; i < ell; i++ {
		bi, err := biArray[i].ToPoint()
		if err != nil {
			return nil, err
		}
		bir := bi.ScalarMult(r)
		msgbir, err := bir.ToEcPointMessage()
		if err != nil {
			return nil, err
		}
		// Instead of p0 = H(sid, g^ab), use p0 = H(sid,g^ab,i) in Section 3.3 ref: Batching Base Oblivious Transfers https://eprint.iacr.org/2021/682.pdf.
		p0[i], err = utils.HashProtos(sid, msgbir,
			&any.Any{
				Value: []byte(strconv.Itoa(i)),
			})
		if err != nil {
			return nil, err
		}
		// Compute bi-T
		birDivideTRpower, err := bi.Add(T.Neg())
		if err != nil {
			return nil, err
		}
		// Compute r*(bi-T)
		birDivideTRpower = birDivideTRpower.ScalarMult(r)
		msgbirDivideTRpower, err := birDivideTRpower.ToEcPointMessage()
		if err != nil {
			return nil, err
		}
		p1[i], err = utils.HashProtos(sid, msgbirDivideTRpower)
		if err != nil {
			return nil, err
		}
		// Challenge Computation
		p0Ro3[i], err = ro3(sid, p0[i])
		if err != nil {
			return nil, err
		}
		pi1Ro3, err := ro3(sid, p1[i])
		if err != nil {
			return nil, err
		}
		chall[i] = utils.Xor(p0Ro3[i], pi1Ro3)
	}
	// proof computation
	challMSg := &OtChallengeMessage{
		Challenge: p0Ro3,
	}
	ans, err := utils.HashProtos(sid, challMSg)
	if err != nil {
		return nil, err
	}
	gamma, err := utils.HashProtos(sid, &any.Any{
		Value: ans,
	})
	if err != nil {
		return nil, err
	}
	zMsg, err := z.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	return &OtSender{
		ans: ans,
		p0:  p0,
		p1:  p1,
		msg: &OtSenderMessage{
			Z:     zMsg,
			Chall: chall,
			Gamma: gamma,
		},
	}, nil
}

func (otSen *OtSender) GetOtSenderMessage() *OtSenderMessage {
	return otSen.msg
}

func (otSen *OtSender) Verify(otVerifyMsg *OtReceiverVerifyMessage) error {
	if subtle.ConstantTimeCompare(otSen.ans, otVerifyMsg.GetAns()) != 1 {
		return ErrFailedVerify
	}
	return nil
}

func ro3(sid []byte, message []byte) ([]byte, error) {
	return utils.HashProtos(sid, &any.Any{
		Value: message,
	})
}

func generateT(sid []byte, seed []byte) (*pt.ECPoint, error) {
	sidSeed := append(sid, uint8(asciiComma))
	sidSeed = append(sidSeed, seed...)
	return secp256k1Hasher.Hash(sidSeed)
}
