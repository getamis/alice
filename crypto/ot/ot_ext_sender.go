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
	"crypto/aes"
	"encoding/binary"
	"math/rand"
	"strconv"

	"github.com/getamis/alice/crypto/binaryfield"
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/ptypes/any"
)

/*
	We implement OT protocol in Fig 5: Blazing Fast OT for Three-round UC OT Extension
*/

type OtExtSender struct {
	otRec *OtReceiver

	m   int
	a0  [][]byte
	a1  [][]byte
	sid []byte
}

func NewExtSender(sid []byte, kappa int, a0 [][]byte, a1 [][]byte) (*OtExtSender, error) {
	if len(a0) != len(a1) {
		return nil, ErrWrongInput
	}
	orR, err := NewReceiver(sid, kappa, kappa)
	if err != nil {
		return nil, err
	}
	return &OtExtSender{
		otRec: orR,
		m:     len(a0),
		a0:    a0,
		a1:    a1,
		sid:   sid,
	}, nil
}

func (s *OtExtSender) GetReceiverMessage() *OtReceiverMessage {
	return s.otRec.GetReceiverMessage()
}

func (s *OtExtSender) GetA0() [][]byte {
	return s.a0
}

func (s *OtExtSender) GetA1() [][]byte {
	return s.a1
}

func (send *OtExtSender) Verify(otExtRMsg *OtExtReceiveMessage) (*OtExtSendResponseMessage, error) {
	verifyMsg, kib, err := send.otRec.Response(otExtRMsg.GetOtSendMsg())
	if err != nil {
		return nil, err
	}
	D := otExtRMsg.GetD()
	maddkappaByteLength := (send.m + len(D)) >> 3
	Q := make([][]uint8, len(D))
	for i := 0; i < len(Q); i++ {
		tempQi, err := utils.HashProtos(send.otRec.sid, &any.Any{
			Value: kib[i],
		})
		if err != nil {
			return nil, err
		}
		Q[i] = utils.Xor(utils.BytesToBits(prg(tempQi, maddkappaByteLength)), utils.ScalarMul(send.otRec.b[i], D[i]))
	}

	chi, err := hashRO2(send.otRec.sid, D)
	if err != nil {
		return nil, err
	}

	w := binaryfield.ScalMulFieldElement(chi[0], getRow(0, Q))
	for i := 1; i < len(chi); i++ {
		w, err = binaryfield.AddVector(w, binaryfield.ScalMulFieldElement(chi[i], getRow(i, Q)))
		if err != nil {
			return nil, err
		}
	}

	uaddsv := binaryProduct(binaryfield.ToFieldElement(otExtRMsg.GetV()), send.otRec.b)
	uaddsv, err = binaryfield.AddVector(uaddsv, binaryfield.ToFieldElement(otExtRMsg.GetU()))
	if err != nil {
		return nil, err
	}
	if !binaryfield.EqualSlice(uaddsv, w) {
		return nil, ErrFailedVerify
	}
	y0 := make([][]byte, send.m)
	y1 := make([][]byte, send.m)

	for i := 0; i < send.m; i++ {
		crfResult, err := crf(send.sid, i, getRow(i, Q))
		if err != nil {
			return nil, err
		}
		y0[i] = utils.Xor(send.a0[i], crfResult)
		crfResult1, err := crf(send.sid, i, utils.Xor(send.otRec.b, getRow(i, Q)))
		if err != nil {
			return nil, err
		}
		y1[i] = utils.Xor(send.a1[i], crfResult1)
	}
	return &OtExtSendResponseMessage{
		A0:             y0,
		A1:             y1,
		OtRecVerifyMsg: verifyMsg,
	}, nil
}

// TODO: Check this function is secure.
func prg(seed []byte, outputByteLength int) []byte {
	seed32 := make([]byte, 4)
	seedLength := len(seed)
	upBound := seedLength >> 2
	copy(seed32, seed[0:4])
	for i := 1; i <= upBound; i++ {
		strart := (i - 1) << 2
		end := strart + 4
		if end >= seedLength {
			seed32 = utils.Xor(seed32, seed[strart:])
			break
		}
		seed32 = utils.Xor(seed32, seed[strart:end])
	}
	result := make([]byte, outputByteLength)
	// #nosec: G404: Use of weak random number generator (math/rand instead of crypto/rand)
	r := rand.New(rand.NewSource(int64(binary.BigEndian.Uint32(seed32))))
	// #nosec: G404: Use of weak random number generator (math/rand instead of crypto/rand)
	r.Read(result)
	return result
}

// Note result[i]: ith-column
func getMatrixM(sid []byte, p0 [][]byte, outputByteLength int) ([][]uint8, error) {
	result := make([][]uint8, len(p0))
	for i := 0; i < len(p0); i++ {
		temp, err := utils.HashProtos(sid, &any.Any{
			Value: p0[i],
		})
		if err != nil {
			return nil, err
		}
		result[i] = utils.BytesToBits(prg(temp, outputByteLength))
	}
	return result, nil
}

// Section 7.2 in Efficient and Secure Multiparty Computation from Fixed-Key Block Ciphers. Ref: https://eprint.iacr.org/2019/074.pdf
// TODO: Get a more nice key
func crf(sid []byte, j int, message []byte) ([]byte, error) {
	byteLength := len(message) >> 3
	jbyte := []byte(strconv.Itoa((j)))
	sidSeed := append(sid, uint8(asciiComma))
	sidSeed = padding(append(sidSeed, jbyte...), byteLength)
	cipher, err := aes.NewCipher(sidSeed)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, byteLength)
	result := make([]byte, byteLength)
	messageByte := padding(message, byteLength)
	cipher.Encrypt(ciphertext, messageByte)
	tempResult := utils.Xor(ciphertext, sidSeed)
	cipher.Encrypt(result, tempResult)
	return result, nil
}

func padding(input []byte, outputLength int) []byte {
	low := len(input)
	long := outputLength
	if low > long {
		low, long = long, low
	}

	result := make([]byte, long)
	for i := 0; i < low; i++ {
		result[i] = input[i]
	}
	for i := low; i < long; i++ {
		result[i] = 0
	}
	return result
}

func binaryProduct(vector []*binaryfield.FieldElement, s []uint8) []*binaryfield.FieldElement {
	result := make([]*binaryfield.FieldElement, len(s))
	for i := 0; i < len(result); i++ {
		if s[i] == 0 {
			result[i] = binaryfield.NewFieldElement(0, 0)
			continue
		}
		result[i] = vector[i].Copy()
	}
	return result
}

// Note: R: ith- column is R[i] = r'.
func getMatrixR(kappa uint, p0 [][]byte, r []uint8, outputByteLength int) ([][]uint8, error) {
	result := make([][]uint8, len(p0))
	rbyte, err := utils.BitsToBytes(r)
	if err != nil {
		return nil, err
	}
	randomrpai, err := utils.GenRandomBytes(int(kappa >> 3))
	if err != nil {
		return nil, err
	}
	tempResult := append(rbyte, randomrpai...)
	tempResult = utils.BytesToBits(tempResult)
	for i := 0; i < len(p0); i++ {
		result[i] = tempResult
	}
	return result, nil
}

func getMatrixD(sid []byte, p1 [][]byte, M [][]uint8, R [][]uint8, outputByteLength int) ([][]uint8, error) {
	result := make([][]uint8, len(p1))
	for i := 0; i < len(p1); i++ {
		temp, err := utils.HashProtos(sid, &any.Any{
			Value: p1[i],
		})
		if err != nil {
			return nil, err
		}
		tempResult := utils.BytesToBits(prg(temp, outputByteLength))
		tempResult = utils.Xor(tempResult, M[i])
		result[i] = utils.Xor(tempResult, R[i])
	}
	return result, nil
}

// TODO: do not check equal length
func computeUandV(chi []*binaryfield.FieldElement, M [][]uint8, R [][]uint8) ([]*binaryfield.FieldElement, []*binaryfield.FieldElement, error) {
	ufieldelement := binaryfield.ScalMulFieldElement(chi[0], getRow(0, M))
	var err error
	vfieldelement := binaryfield.ScalMulFieldElement(chi[0], getRow(0, R))
	for i := 1; i < len(chi); i++ {
		tempfieldelement := binaryfield.ScalMulFieldElement(chi[i], getRow(i, M))
		ufieldelement, err = binaryfield.AddVector(ufieldelement, tempfieldelement)
		if err != nil {
			return nil, nil, err
		}
		tempfieldelement = binaryfield.ScalMulFieldElement(chi[i], getRow(i, R))
		vfieldelement, err = binaryfield.AddVector(vfieldelement, tempfieldelement)
		if err != nil {
			return nil, nil, err
		}
	}
	return ufieldelement, vfieldelement, nil
}

func getRow(indexRow int, input [][]uint8) []uint8 {
	result := make([]uint8, len(input))
	for i := 0; i < len(input); i++ {
		result[i] = input[i][indexRow]
	}
	return result
}

// TODO: We should check this implementation is secure
func hashRO2(sid []byte, D [][]uint8) ([]*binaryfield.FieldElement, error) {
	result := make([]*binaryfield.FieldElement, len(D[0]))
	for i := 0; i < len(result); i++ {
		chiByte, err := utils.HashProtos(sid, &OtDMessage{
			D: getRow(i, D),
		})
		if err != nil {
			return nil, err
		}
		low := chiByte[0:8]
		up := chiByte[8:16]
		tempResult := binaryfield.NewFieldElement(binary.LittleEndian.Uint64(low), binary.LittleEndian.Uint64(up))
		result[i] = tempResult
	}
	return result, nil
}
