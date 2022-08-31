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

package childnewversion

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/bip32/validation"
	"github.com/getamis/alice/crypto/circuit"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/ot"
	"github.com/getamis/alice/crypto/utils"
	"github.com/minio/blake2b-simd"
)

const (
	circuitSecurityLength = 128
	maxRetry              = 100
	nLength               = 33
	rLength               = 256
	mLength               = 256
	shareLength           = 256
	stateLength           = 512
	otherInfoLength       = 768
	// MinHardenKey is the first index of "harded" child key in the bip32 spec
	MinHardenKey = uint32(0x80000000)

	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33
)

var (
	big1        = big.NewInt(1)
	big2        = big.NewInt(2)
	big2Inverse = new(big.Int).ModInverse(big2, curveN)
	uppBdn      = new(big.Int).Lsh(big1, nLength)
	secp256k1   = elliptic.Secp256k1()

	curveN = new(big.Int).Set(secp256k1.Params().N)

	// ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure.")
	// ErrInvalidTranslation is invalid translate
	ErrInvalidTranslation = errors.New("invalid translate")
	// ErrIdentityChildPublicKey is the child public key is identity
	ErrIdentityChildPublicKey = errors.New("identity child public key")
	// ErrNonHardenedKey is returned the index < MinHardenKey
	ErrNonHardenedKey = errors.New("the index can not produce any hardened key")
	// ErrHardenedKey is returned the index >= MinHardenKey
	ErrHardenedKey = errors.New("the index can not produce any nonhardened key")
	// ErrSliceLength is returned if two slices are different.
	ErrSliceLength = errors.New("two slices are different")
)

type participant struct {
	parentShareManager *shareManager
	sid                []byte
	// modifyShare := share - m mod q
	modifyShare *big.Int
	//parentChainCode    []byte
	garCKDCircuit    *circuit.GarbleCircuit
	owngarCKDMsg     *circuit.GarbleCircuitMessage
	ownOTSender      *ot.OtExtSender
	ownOTReceiver    *ot.OtExtReceiver
	childKeyShare    *big.Int
	keyIndex         *big.Int
	r                *big.Int
	n                *big.Int
	m                *big.Int
	nonZeroCKDGWires []byte
	otCKDResult      [][]byte
	otherR           *pt.ECPoint

	validationManager *validation.ValidationManager
}

type shareManager struct {
	share     *big.Int
	publicKey *pt.ECPoint
	// 32 bytes
	chainCode []byte
	depth     uint32
}

type childShare struct {
	*shareManager
	translate *big.Int
}

func NewParticipant(sid []byte, share *big.Int, chaincode []byte, keyIndex *big.Int, pubKey *pt.ECPoint, depth uint32, vad *validation.ValidationManager) *participant {
	return &participant{
		parentShareManager: &shareManager{
			share:     share,
			publicKey: pubKey,
			chainCode: chaincode,
			depth:     depth,
		},
		sid:               sid,
		keyIndex:          keyIndex,
		validationManager: vad,
	}
}

func (sM *shareManager) computeOwnGarbledCircuitInputCKD(childkeyIndex, m, r, n *big.Int) ([]uint8, *big.Int, error) {
	// input: otherInfo, hashState, s1, m1, r1, n1, s2, m2, r2, n2
	preState, err := NewHmacSha512(sM.chainCode).ComputeFirstBlockHash()
	if err != nil {
		return nil, nil, err
	}
	inputSereilize, err := circuit.SetShaStateBristolInput(preState)
	if err != nil {
		return nil, nil, err
	}

	indexKey := make([]uint8, 32)
	for i := 0; i < 32; i++ {
		indexKey[31-i] = uint8(childkeyIndex.Bit(i))
	}
	zeroShaPadding := make([]uint8, 717)
	zeroShaPadding[0] = 1
	countValue := make([]uint8, 11)
	countValue[0] = 1
	countValue[2] = 1
	countValue[5] = 1
	countValue[7] = 1
	zero := make([]uint8, 8)

	otherInfo := make([]uint8, 0)
	otherInfo = append(otherInfo, indexKey...)
	otherInfo = append(otherInfo, zeroShaPadding...)
	otherInfo = append(otherInfo, countValue...)
	otherInfo = append(otherInfo, zero...)
	inputSereilize = append(otherInfo, inputSereilize...)

	modifyShare := new(big.Int).Set(sM.share)
	modifyShare.Sub(modifyShare, m)
	modifyShare.Mod(modifyShare, curveN)
	personInfo := make([]uint8, shareLength+mLength+rLength+nLength)
	for i := 0; i < modifyShare.BitLen(); i++ {
		personInfo[i] = uint8(modifyShare.Bit(i))
	}
	startIndex := shareLength
	for i := 0; i < m.BitLen(); i++ {
		personInfo[i+startIndex] = uint8(m.Bit(i))
	}
	startIndex += mLength
	for i := 0; i < r.BitLen(); i++ {
		personInfo[i+startIndex] = uint8(r.Bit(i))
	}
	startIndex += rLength
	for i := 0; i < n.BitLen(); i++ {
		personInfo[i+startIndex] = uint8(n.Bit(i))
	}
	inputSereilize = append(inputSereilize, personInfo...)
	return inputSereilize, modifyShare, nil
}

func (p *participant) Round1() (*Round1Message, error) {
	curveN := secp256k1.Params().N
	m, err := utils.RandomCoprimeInt(curveN)
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomCoprimeInt(curveN)
	if err != nil {
		return nil, err
	}
	n, err := utils.RandomPositiveInt(uppBdn)
	if err != nil {
		return nil, err
	}
	if n.Bit(0) != 1 {
		n.Xor(n, big1)
	}
	cirCKD, err := circuit.LoadBristol("../../circuit/bristolFashion/ckd.txt")
	if err != nil {
		return nil, err
	}

	ckdInput, modifyShare, err := p.parentShareManager.computeOwnGarbledCircuitInputCKD(p.keyIndex, m, r, n)
	if err != nil {
		return nil, err
	}
	garckd, garckdMsg, err := cirCKD.Garbled(circuitSecurityLength, ckdInput, circuit.EncryptFunc(0))

	// Remove the ot part of ckd
	totalLength := otherInfoLength + stateLength + shareLength + mLength + rLength + nLength
	verifyckd := make([][]byte, totalLength)
	copy(verifyckd, garckdMsg.X[:totalLength])
	garckdMsg.X = verifyckd

	// set inInformation
	p.r = r
	p.n = n
	p.m = m
	p.modifyShare = modifyShare
	p.garCKDCircuit = garckd
	p.owngarCKDMsg = garckdMsg

	// Prepare the first message of OT. Should omit the zero index of n.
	// Recall the order of input is hashotherInfo, hashstate, share1, m1, r1, n1, share2, m2, r2, n2
	otCKDStartIndex := otherInfoLength + stateLength + shareLength + mLength + rLength + nLength
	otCKDEndIndex := otherInfoLength + stateLength + ((shareLength + mLength + rLength) << 1) + nLength
	A0, A1 := garckd.GenerateGarbleWire(otCKDStartIndex, otCKDEndIndex)
	otCKDStartIndex = otCKDEndIndex
	otCKDEndIndex = otCKDEndIndex + nLength
	tempA0, tempA1 := garckd.GenerateGarbleWire(otCKDStartIndex, otCKDEndIndex)

	A0 = append(A0, tempA0[1:]...)
	A1 = append(A1, tempA1[1:]...)
	garWireCKDZeroIndex := tempA1[0]

	otExtS, err := ot.NewExtSender(p.sid, circuitSecurityLength, A0, A1)
	if err != nil {
		return nil, err
	}
	p.ownOTSender = otExtS
	return &Round1Message{
		NgarbledWireCKD: garWireCKDZeroIndex,
		OtReceiverMsg:   otExtS.GetReceiverMessage(),
	}, nil
}

func (p *participant) Round2(round1Msg *Round1Message) (*Round2Message, error) {
	p.nonZeroCKDGWires = round1Msg.NgarbledWireCKD
	// omit the zero index of n
	otInput := make([]byte, shareLength+nLength-1+rLength+mLength)
	for i := 0; i < p.modifyShare.BitLen(); i++ {
		otInput[i] = uint8(p.modifyShare.Bit(i))
	}
	for i := 0; i < p.m.BitLen(); i++ {
		otInput[i+shareLength] = uint8(p.m.Bit(i))
	}
	translate := shareLength + mLength
	for i := 0; i < p.r.BitLen(); i++ {
		otInput[i+translate] = uint8(p.r.Bit(i))
	}
	translate = translate + rLength
	for i := 0; i < p.n.BitLen()-1; i++ {
		otInput[i+translate] = uint8(p.n.Bit(i + 1))
	}

	otExtR, err := ot.NewExtReceiver(p.sid, otInput, round1Msg.OtReceiverMsg)
	if err != nil {
		return nil, err
	}
	p.ownOTReceiver = otExtR
	return &Round2Message{
		OtExtReceiveMsg: otExtR.GetOtExtReceiveMessage(),
	}, nil
}

func (p *participant) Round3(round2Msg *Round2Message) (*Round3Message, error) {
	otExtSendResMsg, err := p.ownOTSender.Verify(round2Msg.OtExtReceiveMsg)
	if err != nil {
		return nil, err
	}
	return &Round3Message{
		OtExtSResponse: otExtSendResMsg,
	}, nil
}

func (p *participant) Round4(round3Msg *Round3Message) (*Round4Message, error) {
	otResult, err := p.ownOTReceiver.GetOTFinalResult(round3Msg.OtExtSResponse)
	if err != nil {
		return nil, err
	}
	rG := pt.ScalarBaseMult(secp256k1, p.r)
	rgMsg, err := rG.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	// data: share2, m2, r2, n2
	// Set the complete wire-labels of ckd
	divideIndex := shareLength + mLength + rLength
	ckdResult := make([][]byte, divideIndex)
	copy(ckdResult, otResult[0:divideIndex])
	ckdResult = append(ckdResult, p.nonZeroCKDGWires)
	p.otCKDResult = append(ckdResult, otResult[divideIndex:]...)
	return &Round4Message{
		RG: rgMsg,
	}, nil
}

func (p *participant) Round5(round4Msg *Round4Message) (*Round5Message, error) {
	otherR, err := round4Msg.RG.ToPoint()
	if err != nil {
		return nil, err
	}
	p.otherR = otherR

	return &Round5Message{
		GarcirMsg: p.owngarCKDMsg,
	}, nil
}

func (p *participant) Round6(round5Msg *Round5Message, isOTSender bool) (*childShare, error) {
	curve := p.parentShareManager.publicKey.GetCurve()
	// input : hashotherInfo, hashstate, share1, m1, r1, n1, share2, m2, r2, n2
	ckdGarbledWireLabel := make([][]byte, stateLength+otherInfoLength+shareLength+mLength+rLength+nLength)
	copy(ckdGarbledWireLabel, round5Msg.GarcirMsg.X)
	ckdGarbledWireLabel = append(ckdGarbledWireLabel, p.otCKDResult...)

	evaluation, err := p.garCKDCircuit.EvaluateGarbleCircuit(round5Msg.GarcirMsg, ckdGarbledWireLabel)
	if err != nil {
		return nil, err
	}
	// output: [0:512]: I, [512:768]: s1+m1+s2+m2+r1n2+n1r2 mod q, and [768:]: n1+n2
	plaintextOfCKD := circuit.Decrypt(round5Msg.GarcirMsg.GetD(), evaluation)
	I, err := utils.BitsToBytes(utils.ReverseByte(plaintextOfCKD[0:512]))
	if err != nil {
		return nil, err
	}

	w, err := circuit.DecodeBristolFashionOutput(plaintextOfCKD[512:768])
	if err != nil {
		return nil, err
	}
	wValue, _ := new(big.Int).SetString(w, 16)
	sumN := bitArrayToInt(plaintextOfCKD[768:])
	otherN := new(big.Int).Sub(sumN, p.n)
	// check
	wG := pt.ScalarBaseMult(curve, wValue)
	compare := pt.ScalarBaseMult(curve, p.r)
	compare = compare.ScalarMult(otherN)
	compare, err = compare.Add(p.otherR.ScalarMult(p.n))
	if err != nil {
		return nil, err
	}
	compare, err = compare.Add(p.parentShareManager.publicKey)
	if err != nil {
		return nil, err
	}
	if !compare.Equal(wG) {
		return nil, ErrVerifyFailure
	}
	childShare, err := p.parentShareManager.ComputeHardenedChildShare(uint32(p.keyIndex.Int64()), I)
	if err != nil {
		return nil, err
	}

	// Compute Validation information:
	wv, err := getWv(p.garCKDCircuit.GetOutputWire(), round5Msg.GarcirMsg.HOutputWire0, round5Msg.GarcirMsg.HOutputWire1, evaluation)
	if err != nil {
		return nil, err
	}
	var bs [32]byte
	inputData := make([]byte, len(p.sid))
	copy(inputData, p.sid)
	if isOTSender {
		inputData = append(inputData, byte(','))
		for _, w := range wv {
			inputData = append(inputData, w...)
		}
		inputData = append(inputData, byte(','))
		for _, e := range evaluation {
			inputData = append(inputData, e...)
		}
		bs = blake2b.Sum256(inputData)
	} else {
		inputData = append(inputData, byte(','))
		for _, e := range evaluation {
			inputData = append(inputData, e...)
		}
		inputData = append(inputData, byte(','))
		for _, w := range wv {
			inputData = append(inputData, w...)
		}
		bs = blake2b.Sum256(inputData)
	}
	p.validationManager.OverWriteh(new(big.Int).SetBytes(bs[:]))
	return childShare, nil
}

func bitArrayToInt(array []uint8) *big.Int {
	result := new(big.Int).SetInt64(int64(array[0]))
	twoPower := big.NewInt(2)
	for i := 1; i < len(array); i++ {
		if array[i] == 1 {
			result.Add(result, twoPower)
		}
		twoPower.Lsh(twoPower, 1)
	}
	return result
}

func (pm *shareManager) ComputeHardenedChildShare(childIndex uint32, secondState []byte) (*childShare, error) {
	if childIndex < MinHardenKey {
		return nil, ErrNonHardenedKey
	}
	curve := secp256k1
	curveN := curve.Params().N
	hashResult := NewHmacSha512(pm.chainCode).Digest(secondState)
	translate := new(big.Int).SetBytes(hashResult[0:32])
	if translate.Cmp(curveN) > 0 {
		return nil, ErrInvalidTranslation
	}

	// Because now we have two people, so we modify this value such such that s1+1/.2*translate + s2 + 1/2*translate = privatekey
	halfTranslate := new(big.Int).ModInverse(big2, curveN)
	halfTranslate.Mul(halfTranslate, translate)
	halfTranslate.Mod(halfTranslate, curveN)
	childPubKey := pt.ScalarBaseMult(curve, translate)
	childPubKey, err := pm.publicKey.Add(childPubKey)
	if err != nil {
		return nil, err
	}
	if childPubKey.IsIdentity() {
		return nil, ErrIdentityChildPublicKey
	}

	cs := new(big.Int).Add(pm.share, halfTranslate)
	cs = cs.Mod(cs, curveN)
	return &childShare{
		translate: translate,
		shareManager: &shareManager{
			share:     cs,
			chainCode: hashResult[32:],
			depth:     pm.depth + 1,
			publicKey: childPubKey,
		},
	}, nil
}

func (sHolder *shareManager) ComputeNonHardenedChildShare(childIndex uint32) (*childShare, error) {
	curve := sHolder.publicKey.GetCurve()
	if childIndex >= MinHardenKey {
		return nil, ErrHardenedKey
	}
	childIndexBytes := uint32Bytes(childIndex)
	data := compressPublicKey(sHolder.publicKey)
	data = append(data, childIndexBytes...)

	hmac := hmac.New(sha512.New, sHolder.chainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	hashResult := hmac.Sum(nil)
	translate := new(big.Int).SetBytes(hashResult[0:32])
	curveN := curve.Params().N
	if translate.Cmp(curveN) > 0 {
		return nil, ErrInvalidTranslation
	}
	childPubKey, err := sHolder.publicKey.Add(pt.ScalarBaseMult(curve, translate))
	if err != nil {
		return nil, err
	}
	if childPubKey.IsIdentity() {
		return nil, ErrIdentityChildPublicKey
	}

	cs := new(big.Int).Add(sHolder.share, translate)
	cs = cs.Mod(cs, sHolder.publicKey.GetCurve().Params().N)
	return &childShare{
		translate: translate,
		shareManager: &shareManager{
			publicKey: childPubKey,
			share:     cs,
			chainCode: hashResult[32:],
			depth:     sHolder.depth + 1,
		},
	}, nil
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

func compressPublicKey(pubKey *pt.ECPoint) []byte {
	var key bytes.Buffer
	x := pubKey.GetX()
	y := pubKey.GetY()
	// Write header; 0x2 for even y value; 0x3 for odd
	key.WriteByte(byte(0x2) + byte(y.Bit(0)))

	// Write X coord; Pad the key so x is aligned with the LSB. Pad size is key length - header size (1) - xBytes size
	xBytes := x.Bytes()
	for i := 0; i < (PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)
	return key.Bytes()
}

func getWv(ownOutputWire [][][]byte, hashW0 [][]byte, hashW1 [][]byte, evaluateResult [][]byte) ([][]byte, error) {
	if len(hashW0) != len(hashW1) {
		return nil, ErrSliceLength
	}
	if len(hashW0) != len(evaluateResult) {
		return nil, ErrSliceLength
	}
	result := make([][]byte, len(evaluateResult))
	for i := 0; i < len(result); i++ {
		tempHash := blake2b.Sum256(evaluateResult[i])
		if subtle.ConstantTimeCompare(tempHash[:], hashW0[i]) == 1 {
			result[i] = ownOutputWire[i][0]
			continue
		}
		if subtle.ConstantTimeCompare(tempHash[:], hashW1[i]) == 1 {
			result[i] = ownOutputWire[i][1]
			continue
		}
		return nil, ErrVerifyFailure
	}
	return result, nil
}
