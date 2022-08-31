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

package masternewversion

import (
	"crypto/subtle"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/circuit"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/ot"
	"github.com/getamis/alice/crypto/utils"
	"github.com/minio/blake2b-simd"
	vad "github.com/getamis/alice/crypto/bip32/validation"

)

const (
	circuitSecurityLength = 128
	maxRetry              = 100
	nLength               = 33
	rLength               = 256
	seedLength            = 512
	stateLength           = 512
)

var (
	big1        = big.NewInt(1)
	big2        = big.NewInt(2)
	big2Inverse = new(big.Int).ModInverse(big2, curveN)
	uppBdn      = new(big.Int).Lsh(big1, nLength)
	secp256k1   = elliptic.Secp256k1()

	curveN = new(big.Int).Set(secp256k1.Params().N)

	// ErrILTOOLARGE is returned if the value of IL is larger than curveN.
	ErrILTOOLARGE = errors.New("the value of IL is larger than curveN")
	// ErrTWOCIRCUITWRONG is returned if the relation of two circuits does not hold.
	ErrTWOCIRCUITWRONG = errors.New("the the relation of two circuits does not hold.")
	// ErrSliceLength is returned if two slices are different.
	ErrSliceLength = errors.New("two slices are different")
	// ErrVerifyFailure is returned the verify failures.
	ErrVerifyFailure = errors.New("the verify failures")
)

type participant struct {
	sid             []byte
	seed            []uint8
	garMKGCircuit   *circuit.GarbleCircuit
	garauxCircuit   *circuit.GarbleCircuit
	owngarMKGMsg    *circuit.GarbleCircuitMessage
	owngarauxMsg    *circuit.GarbleCircuitMessage
	ownOTSender     *ot.OtExtSender
	ownOTReceiver   *ot.OtExtReceiver
	masterKeyShare  *big.Int
	r               *big.Int
	n               *big.Int
	nonZeroMKGWires []byte
	nonZeroauxWires []byte
	otauxResult     [][]byte
	otMKGResult     [][]byte
	v_aux           *big.Int

	otherR          *pt.ECPoint
	masterKeyPubKey *pt.ECPoint

	validationManager *vad.ValidationManager
}

func NewParticipant(sid []byte, vad *vad.ValidationManager) *participant {
	return &participant{
		sid: sid,
		validationManager: vad,
	}
}

func computeOwnGarbledCircuitInputAux(seed []uint8, r *big.Int) ([]uint8, error) {
	// input: seed1, r1, seed2, n2, otherInfo, hashState1, hashState2
	input := make([][]uint8, 7)
	input[0] = seed[0:]
	input[1] = make([]uint8, rLength)
	input[2] = make([]uint8, seedLength)
	input[3] = make([]uint8, nLength)
	input[4] = make([]uint8, stateLength)
	input[5] = make([]uint8, stateLength)
	input[6] = make([]uint8, stateLength)

	var err error
	firstState := []uint64{3326739937957255283, 8688772341620556602, 15932180217903289146,
		16593632695233548967, 18143991045780064928, 11715845138021987934, 18298647192286487112,
		3456966267567238595}
	input[5], err = circuit.SetShaStateBristolInput(firstState)
	if err != nil {
		return nil, err
	}
	firstStateOther := []uint64{13534015809423056317, 15928041516761626561, 16131116959625208868,
		2955168835985126220, 11749762402537216508, 7612603733104932751, 360328074546165396,
		17786688585256325943}
	input[6], err = circuit.SetShaStateBristolInput(firstStateOther)
	if err != nil {
		return nil, err
	}
	otherInfo := make([]uint8, 501)
	otherInfo[0] = 1
	countValue := make([]uint8, 11)
	countValue[0] = 1
	countValue[1] = 1
	otherInfo = append(otherInfo, countValue...)
	input[4] = otherInfo

	for i := 0; i < r.BitLen(); i++ {
		input[1][i] = uint8(r.Bit(i))
	}
	inputSereilize := input[0]
	inputSereilize = append(inputSereilize, input[1]...)
	inputSereilize = append(inputSereilize, input[2]...)
	inputSereilize = append(inputSereilize, input[3]...)
	inputSereilize = append(inputSereilize, input[4]...)
	inputSereilize = append(inputSereilize, input[5]...)
	inputSereilize = append(inputSereilize, input[6]...)
	return inputSereilize, nil
}

func computeOwnGarbledCircuitInputMKG(seed []uint8, r, n *big.Int) ([]uint8, error) {
	// input: seed1, r1, n1, seed2, r2, n2, hmacotherInfo, hashState1, hashState2
	input := make([][]uint8, 9)
	input[0] = seed[:seedLength]
	input[1] = make([]uint8, rLength)
	input[2] = make([]uint8, nLength)
	input[3] = make([]uint8, seedLength)
	input[4] = make([]uint8, rLength)
	input[5] = make([]uint8, nLength)
	input[6] = make([]uint8, stateLength)
	input[7] = make([]uint8, stateLength)
	input[8] = make([]uint8, stateLength)
	var err error
	firstState := []uint64{3326739937957255283, 8688772341620556602, 15932180217903289146,
		16593632695233548967, 18143991045780064928, 11715845138021987934, 18298647192286487112,
		3456966267567238595}
	input[7], err = circuit.SetShaStateBristolInput(firstState)
	if err != nil {
		return nil, err
	}
	firstStateOther := []uint64{13534015809423056317, 15928041516761626561, 16131116959625208868,
		2955168835985126220, 11749762402537216508, 7612603733104932751, 360328074546165396,
		17786688585256325943}
	input[8], err = circuit.SetShaStateBristolInput(firstStateOther)
	if err != nil {
		return nil, err
	}
	otherInfo := make([]uint8, 501)
	otherInfo[0] = 1
	countValue := make([]uint8, 11)
	countValue[0] = 1
	countValue[1] = 1
	otherInfo = append(otherInfo, countValue...)
	input[6] = otherInfo

	for i := 0; i < n.BitLen(); i++ {
		input[2][i] = uint8(n.Bit(i))
	}
	for i := 0; i < r.BitLen(); i++ {
		input[1][i] = uint8(r.Bit(i))
	}

	inputSereilize := input[0]
	inputSereilize = append(inputSereilize, input[1]...)
	inputSereilize = append(inputSereilize, input[2]...)
	inputSereilize = append(inputSereilize, input[3]...)
	inputSereilize = append(inputSereilize, input[4]...)
	inputSereilize = append(inputSereilize, input[5]...)
	inputSereilize = append(inputSereilize, input[6]...)
	inputSereilize = append(inputSereilize, input[7]...)
	inputSereilize = append(inputSereilize, input[8]...)
	return inputSereilize, err
}

func (p *participant) Round1(seed []byte) (*Round1Message, error) {
	curveN := secp256k1.Params().N
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
	cirMKG, err := circuit.LoadBristol("../../circuit/bristolFashion/seed.txt")
	if err != nil {
		return nil, err
	}
	ciraux, err := circuit.LoadBristol("../../circuit/bristolFashion/aux.txt")
	if err != nil {
		return nil, err
	}

	auxInput, err := computeOwnGarbledCircuitInputAux(seed, r)
	if err != nil {
		return nil, err
	}
	garaux, garauxMsg, err := ciraux.Garbled(circuitSecurityLength, auxInput, circuit.EncryptFunc(0))
	mkgInput, err := computeOwnGarbledCircuitInputMKG(seed, r, n)
	if err != nil {
		return nil, err
	}
	// Should be careful : X-part fix
	garMKG, garMKGMsg, err := cirMKG.Garbled(circuitSecurityLength, mkgInput, circuit.EncryptFunc(0))
	if err != nil {
		return nil, err
	}
	// Remove the ot part of aux
	verifyauxx := make([][]byte, seedLength+rLength)
	copy(verifyauxx, garauxMsg.X[0:seedLength+rLength])
	verifyauxx = append(verifyauxx, garauxMsg.X[seedLength*2+rLength+nLength:]...)
	garauxMsg.X = verifyauxx
	// Remove the ot part of mkg
	verifyMKGx := make([][]byte, seedLength+rLength+nLength)
	copy(verifyMKGx, garMKGMsg.X[0:seedLength+rLength+nLength])
	verifyMKGx = append(verifyMKGx, garMKGMsg.X[2*(seedLength+rLength+nLength):]...)
	garMKGMsg.X = verifyMKGx

	// set inInformation
	p.r = r
	p.n = n
	p.garMKGCircuit = garMKG
	p.garauxCircuit = garaux
	p.owngarMKGMsg = garMKGMsg
	p.owngarauxMsg = garauxMsg
	p.seed = seed

	// Prepare the first message of OT. Should omit the zero index of n.
	// Recall the order of input is seed1, r1, seed2, n2, otherInfo, hashState1, hashState2
	otAUXStartIndex := seedLength + rLength
	otAUXEndIndex := otAUXStartIndex + seedLength
	A0, A1 := garaux.GenerateGarbleWire(otAUXStartIndex, otAUXEndIndex)
	otAUXStartIndex = 2*seedLength + rLength
	otAUXEndIndex = 2*seedLength + rLength + nLength
	tempA0, tempA1 := garaux.GenerateGarbleWire(otAUXStartIndex, otAUXEndIndex)

	A0 = append(A0, tempA0[1:]...)
	A1 = append(A1, tempA1[1:]...)
	garWireauxZeroIndex := tempA1[0]
	// MKG part: input: seed1, r1, n1, seed2, r2, n2, hmacotherInfo, hashState1, hashState2
	otMKGStartIndex := seedLength + rLength + nLength
	otMKGEndIndex := otMKGStartIndex + seedLength + rLength
	tempA0, tempA1 = garMKG.GenerateGarbleWire(otMKGStartIndex, otMKGEndIndex)
	A0 = append(A0, tempA0...)
	A1 = append(A1, tempA1...)
	otMKGStartIndex = 2*(seedLength+rLength) + nLength
	otMKGEndIndex = (seedLength + rLength + nLength) * 2
	tempA0, tempA1 = garMKG.GenerateGarbleWire(otMKGStartIndex, otMKGEndIndex)
	garWireMKGZeroIndex := tempA1[0]

	A0 = append(A0, tempA0[1:]...)
	A1 = append(A1, tempA1[1:]...)

	otExtS, err := ot.NewExtSender(p.sid, circuitSecurityLength, A0, A1)
	if err != nil {
		return nil, err
	}
	p.ownOTSender = otExtS
	return &Round1Message{
		NgarbledWireMKG: garWireMKGZeroIndex,
		NgarbledWireaux: garWireauxZeroIndex,
		OtReceiverMsg:   otExtS.GetReceiverMessage(),
	}, nil
}

func (p *participant) Round2(round1Msg *Round1Message) (*Round2Message, error) {
	p.nonZeroMKGWires = round1Msg.NgarbledWireMKG
	p.nonZeroauxWires = round1Msg.NgarbledWireaux
	// omit the zero index of n
	// aux part
	otInput := make([]byte, seedLength+nLength-1+seedLength+rLength+nLength-1)
	for i := 0; i < seedLength; i++ {
		otInput[i] = p.seed[i]
	}
	for i := 0; i < nLength-1; i++ {
		otInput[i+512] = uint8(p.n.Bit(i + 1))
	}
	// MKG part
	translate := seedLength + nLength - 1
	for i := 0; i < seedLength; i++ {
		otInput[i+translate] = p.seed[i]
	}
	translate = translate + seedLength
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
	// data: seed, r, seed, n
	// Set the complete wire-labels of aux
	auxResult := make([][]byte, seedLength)
	copy(auxResult, otResult[0:seedLength])
	auxResult = append(auxResult, p.nonZeroauxWires)
	index := seedLength + nLength - 1
	p.otauxResult = append(auxResult, otResult[seedLength:index]...)
	// Set the complete wire-labels of MKG
	MKGResult := make([][]byte, rLength+seedLength)
	copy(MKGResult, otResult[index:index+rLength+seedLength])
	MKGResult = append(MKGResult, p.nonZeroMKGWires)
	p.otMKGResult = append(MKGResult, otResult[index+rLength+seedLength:]...)

	return &Round4Message{
		RG:        rgMsg,
		GarcirMsg: p.owngarauxMsg,
	}, nil
}

func (p *participant) Round5(round4Msg *Round4Message) (*Round5Message, error) {
	otherR, err := round4Msg.RG.ToPoint()
	if err != nil {
		return nil, err
	}
	// s0, r0, s1, n1, otherPart
	auxGarbledWireLabel := make([][]byte, seedLength+rLength)
	copy(auxGarbledWireLabel, round4Msg.GarcirMsg.X[0:seedLength+rLength])
	auxGarbledWireLabel = append(auxGarbledWireLabel, p.otauxResult...)
	auxGarbledWireLabel = append(auxGarbledWireLabel, round4Msg.GarcirMsg.X[seedLength+rLength:]...)

	evaluation, err := p.garauxCircuit.EvaluateGarbleCircuit(round4Msg.GarcirMsg, auxGarbledWireLabel)
	if err != nil {
		return nil, err
	}
	vPlaintextOfauv := circuit.Decrypt(round4Msg.GarcirMsg.GetD(), evaluation)
	vPlaintextOfauvHex, err := circuit.DecodeBristolFashionOutput(vPlaintextOfauv[0:256])
	if err != nil {
		return nil, err
	}
	v_aux, _ := new(big.Int).SetString(vPlaintextOfauvHex, 16)
	publicKey := pt.ScalarBaseMult(secp256k1, v_aux)
	publicKey, err = publicKey.Add(otherR.ScalarMult(p.n).Neg())
	if err != nil {
		return nil, err
	}
	isILinRange := vPlaintextOfauv[256:257][0]
	if isILinRange == 0 {
		return nil, ErrILTOOLARGE
	}

	p.v_aux = v_aux
	p.otherR = otherR
	p.masterKeyPubKey = publicKey

	hashResult := blake2b.Sum256([]byte(publicKey.String()))
	p.validationManager.OverWriteh(new(big.Int).SetBytes(hashResult[:]))
	return &Round5Message{
		GarcirMsg: p.owngarMKGMsg,
	}, nil
}

func (p *participant) Round6(round5Msg *Round5Message, isOTSender bool) (*big.Int, []byte, error) {
	// s0, r0, n0, s1, r1, n1, otherPart
	index := seedLength + rLength + nLength
	MKGGarbledWireLabel := make([][]byte, index)
	copy(MKGGarbledWireLabel, round5Msg.GarcirMsg.X[0:index])
	MKGGarbledWireLabel = append(MKGGarbledWireLabel, p.otMKGResult...)
	MKGGarbledWireLabel = append(MKGGarbledWireLabel, round5Msg.GarcirMsg.X[index:]...)
	evaluation, err := p.garMKGCircuit.EvaluateGarbleCircuit(round5Msg.GarcirMsg, MKGGarbledWireLabel)
	if err != nil {
		return nil, nil, err
	}

	got := circuit.Decrypt(round5Msg.GarcirMsg.D, evaluation)
	n := bitArrayToInt(got[0 : nLength+1])
	othern := new(big.Int).Sub(n, p.n)
	gotInt, err := circuit.DecodeBristolFashionOutput(got[nLength+1 : nLength+257])
	if err != nil {
		return nil, nil, err
	}
	compareShare, _ := new(big.Int).SetString(gotInt, 16)
	// check
	comparePart := new(big.Int).Mul(othern, p.r)
	comparePart.Add(comparePart, p.v_aux)
	comparePart.Mod(comparePart, curveN)
	if comparePart.Cmp(compareShare) != 0 {
		return nil, nil, ErrTWOCIRCUITWRONG
	}

	I_R, err := circuit.DecodeBristolFashionOutput(got[nLength+257:])
	if err != nil {
		return nil, nil, err
	}
	share := new(big.Int).Mul(othern, p.r)
	compareShare.Mul(compareShare, big2Inverse)
	share.Sub(compareShare, share)
	share.Mod(share, curveN)

	// Compute Validation information:
	wv, err := getWv(p.garMKGCircuit.GetOutputWire(), round5Msg.GarcirMsg.HOutputWire0, round5Msg.GarcirMsg.HOutputWire1, evaluation)
	if err != nil {
		return nil, nil, err
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

	return share, []byte(I_R), nil
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
