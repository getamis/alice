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

package circuit

import (
	"bufio"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strconv"

	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/sirius/log"
	"github.com/minio/blake2b-simd"
)

type Gate string

const (
	XOR Gate = "XOR"
	AND Gate = "AND"
	INV Gate = "INV" // Also called NOT
	EQ  Gate = "EQ"

	KBitMod8 = 16 // 8*16=128
	AES128   = 128
	AES256   = 256
	maxTry   = 100
)

/*
	We implement a version of "garbled Circuit" according to paper: "Better Concrete Security for Half-Gates Garbling"
	and "Two Halves Make a Whole Reducing data Transfer in Garbled Circuits using Half Gates".
	We support the parse of Bristol fashion ref: https://homes.esat.kuleuven.be/~nsmart/MPC/
*/

var (
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)

	// ErrNONSUPPORTGATE is returned if the gate is not supportted.
	ErrNONSUPPORTGATE = errors.New("the gate is not supportted")
	// ErrPARSEFAILURE is returned if the parse failures.
	ErrPARSEFAILURE = errors.New("the parse failures")
	// ErrNOIMPLEMENT is returned if the gate is not implemented.
	ErrNOIMPLEMENT = errors.New("the gate is not implemented")
	// ErrInputBit is returned if the bit input is wrong.
	ErrInputBit = errors.New("the bit input is wrong")
	// ErrInputSize is returned if the size of input is wrong.
	ErrInputSize = errors.New("the size of input is wrong")
)

type gate struct {
	inputWire  []int
	outputWire []int
	gate       Gate
}

func newGate(inputWire, outputWire []int, singlegate Gate) *gate {
	return &gate{
		inputWire:  inputWire,
		outputWire: outputWire,
		gate:       singlegate,
	}
}

// ----

type EncFunc func(*GarbleCircuit, []uint8) ([][]byte, error)

func EncryptFunc(startIndex int) EncFunc {
	return func(g *GarbleCircuit, input []uint8) ([][]byte, error) {
		return g.Encrypt(startIndex, input), nil
	}
}

type GarbleCircuit struct {
	circuit *Circuit

	E          [][]byte
	d          []int32
	R          []byte
	outputWire [][][]byte
}

func (garcir *GarbleCircuit) GenerateGarbleWire(startIndex, endIndex int) ([][]byte, [][]byte) {
	countBobWire := endIndex - startIndex
	W0 := make([][]byte, countBobWire)
	W1 := make([][]byte, countBobWire)
	for i := startIndex; i < endIndex; i++ {
		W0[i-startIndex] = garcir.E[i]
		W1[i-startIndex] = utils.Xor(garcir.E[i], garcir.R)
	}
	return W0, W1
}

func (garcir *GarbleCircuit) Encrypt(startIndex int, input []uint8) [][]byte {
	result := make([][]byte, len(input))
	for i := 0; i < len(result); i++ {
		// Xi := ei xor xiR
		xiR := utils.BinaryMul(uint8(input[i]), garcir.R)
		result[i] = utils.Xor(garcir.E[startIndex+i], xiR)
	}
	return result
}

// Evaluate: procedure Ev
func (garcir *GarbleCircuit) EvaluateGarbleCircuit(garbledMsg *GarbleCircuitMessage, input [][]byte) ([][]byte, error) {
	count := new(big.Int).SetBytes(garbledMsg.StartCount)
	cir := garcir.circuit
	// Set i in Inputs
	W := make([][]byte, cir.countWires)
	inputSize := cir.totalInputSize()
	for i := 0; i < inputSize; i++ {
		W[i] = input[i]
	}

	indexCount := 0
	for i := 0; i < len(cir.gates); i++ {
		g := cir.gates[i]
		if g.gate == XOR {
			W[g.outputWire[0]] = utils.Xor(W[g.inputWire[0]], W[g.inputWire[1]])
			continue
		}
		if g.gate == AND {
			F := garbledMsg.F[indexCount]
			// sa = lsb(Wa), sb = lsb(Wb)
			Wa := W[g.inputWire[0]]
			Wb := W[g.inputWire[1]]
			sa := lsb(Wa)
			sb := lsb(Wb)
			tempCount := new(big.Int).Add(count, big1)
			count.Add(count, big2)
			// (T_Gi, T_Ei) := Fi
			// W_Gi = H(Wa,j) xor saT_Gi
			saTGi := utils.BinaryMul(sa, F.TG)
			WGi, _ := h(Wa, tempCount)
			WGi = utils.Xor(WGi, saTGi)
			// W_Ei = H(Wb,j') xor sa(T_Ei xor Wa)
			sbTEiWa := utils.Xor(F.TE, Wa)
			sbTEiWa = utils.BinaryMul(sb, sbTEiWa)
			WEi, _ := h(Wb, count)
			WEi = utils.Xor(WEi, sbTEiWa)
			W[g.outputWire[0]] = utils.Xor(WGi, WEi)
			indexCount++
			continue
		}
		if g.gate == INV {
			W[g.outputWire[0]] = W[g.inputWire[0]]
			continue
		}
		if g.gate == EQ {
			W[g.outputWire[0]] = W[g.inputWire[0]]
			continue
		}
		return nil, ErrNONSUPPORTGATE
	}
	// Set the output of the evaluating result.
	Y := make([][]byte, cir.totalOutputSize())
	countIndex := 0
	outputIndex := cir.countWires - cir.totalOutputSize()
	for i := 0; i < len(cir.outputSize); i++ {
		for j := 0; j < cir.outputSize[i]; j++ {
			Y[countIndex] = W[outputIndex+countIndex]
			countIndex++
		}
	}
	return Y, nil
}

// ----
type Circuit struct {
	countWires         int
	countGates         int
	garblerInputSize   int
	evaluatorInputSize int
	inputSize          []int
	outputSize         []int
	gates              []*gate
}

func LoadBristol(path string) (*Circuit, error) {
	// Read from file
	readInput, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer readInput.Close()
	scanner := bufio.NewScanner(readInput)
	scanner.Split(bufio.ScanWords)

	// read countGates/countWires
	countGates, _ := strconv.Atoi(readText(scanner))
	countWires, _ := strconv.Atoi(readText(scanner))

	// read input
	inputSize, _ := strconv.Atoi(readText(scanner))
	inputCircuit := make([]int, inputSize)
	for i := 0; i < len(inputCircuit); i++ {
		value, _ := strconv.Atoi(readText(scanner))
		inputCircuit[i] = value
	}

	// read output
	outputSize, _ := strconv.Atoi(readText(scanner))
	outputCircuit := make([]int, outputSize)
	for i := 0; i < len(outputCircuit); i++ {
		value, _ := strconv.Atoi(readText(scanner))
		outputCircuit[i] = value
	}

	// read gates
	gates := make([]*gate, countGates)
	for i := 0; i < len(gates); i++ {
		numberInputWire, _ := strconv.Atoi(readText(scanner))
		numberOutputWire, _ := strconv.Atoi(readText(scanner))

		// read input wires
		inputWire := make([]int, numberInputWire)
		for j := 0; j < len(inputWire); j++ {
			inputWire[j], _ = strconv.Atoi(readText(scanner))
		}
		// read output wires
		outputWire := make([]int, numberOutputWire)
		for j := 0; j < len(outputWire); j++ {
			outputWire[j], _ = strconv.Atoi(readText(scanner))
		}

		// read a bool operation
		gate := Gate(readText(scanner))
		switch gate {
		// Valid gate
		case AND, XOR, INV, EQ:
		default:
			log.Warn("Unsupported gate", "gate", gate)
			return nil, ErrNONSUPPORTGATE
		}
		gates[i] = newGate(inputWire, outputWire, gate)
	}
	return &Circuit{
		countWires: countWires,
		countGates: countGates,
		inputSize:  inputCircuit,
		outputSize: outputCircuit,
		gates:      gates,
	}, nil
}

func (cir *Circuit) totalInputSize() int {
	result := 0
	for i := 0; i < len(cir.inputSize); i++ {
		result += cir.inputSize[i]
	}
	return result
}

func (cir *Circuit) totalOutputSize() int {
	result := 0
	for i := 0; i < len(cir.outputSize); i++ {
		result += cir.outputSize[i]
	}
	return result
}

// Garbled Circuit: Two Halves Make a Whole Reducing data Transfer in Garbled Circuits using Half Gates Fig-2.
// The permitted inputs of Kbit are 128 or 256
func (cir *Circuit) Garbled(kBit int, input []uint8, f EncFunc) (*GarbleCircuit, *GarbleCircuitMessage, error) {
	if kBit != AES128 && kBit != AES256 {
		return nil, nil, ErrInputBit
	}

	// Generate Random kBit Integer
	var count *big.Int
	var err error
	shiftKBits := new(big.Int).Lsh(big1, uint(kBit))
	for i := 0; i < maxTry; i++ {
		count, err = utils.RandomInt(shiftKBits)
		if err != nil {
			return nil, nil, err
		}
		if count.BitLen() == kBit {
			break
		}
	}
	startCount := new(big.Int).Set(count)

	// Get R = {0,1}^{k-1}1 0x01
	KBitMod8 := kBit >> 3
	R, err := utils.GenRandomBytes(KBitMod8)
	if err != nil {
		return nil, nil, err
	}
	R[len(R)-1] |= 1

	// Set i in Inputs
	W := make([][][]byte, cir.countWires)
	for i := 0; i < len(W); i++ {
		W[i] = make([][]byte, 2)
	}

	// Generate the Circuit of inputs
	inputSize := cir.totalInputSize()
	e := make([][]byte, inputSize)
	for i := 0; i < inputSize; i++ {
		Wi, err := utils.GenRandomBytes(KBitMod8)
		if err != nil {
			return nil, nil, err
		}
		W[i] = [][]byte{
			Wi,
			utils.Xor(Wi, R),
		}
		e[i] = Wi
	}

	// Generate others Circuit: XOR/AND/INV/EQ
	var F []*HalfGateMessage
	for i := int32(0); i < int32(len(cir.gates)); i++ {
		g := cir.gates[i]
		switch g.gate {
		case XOR:
			W[g.outputWire[0]][0] = utils.Xor(W[g.inputWire[0]][0], W[g.inputWire[1]][0])
			W[g.outputWire[0]][1] = utils.Xor(W[g.outputWire[0]][0], R)
		case AND:
			var tempTG, tempTE []byte
			tempCount := new(big.Int).Add(count, big1)
			count.Add(count, big2)
			W[g.outputWire[0]][0], tempTG, tempTE, err = gbAnd(W[g.inputWire[0]][0], W[g.inputWire[0]][1], W[g.inputWire[1]][0], W[g.inputWire[1]][1], R, tempCount, count)
			if err != nil {
				return nil, nil, err
			}
			W[g.outputWire[0]][1] = utils.Xor(W[g.outputWire[0]][0], R)
			F = append(F, &HalfGateMessage{
				TG:        tempTG,
				TE:        tempTE,
				WireIndex: i,
			})
		case INV:
			W[g.outputWire[0]][0] = utils.Xor(W[g.inputWire[0]][0], R)
			W[g.outputWire[0]][1] = utils.Xor(W[g.outputWire[0]][0], R)
		case EQ:
			W[g.outputWire[0]][0] = W[g.inputWire[0]][0]
			W[g.outputWire[0]][1] = utils.Xor(W[g.outputWire[0]][0], R)
		default:
			return nil, nil, ErrNONSUPPORTGATE
		}
	}

	// Set the output of the garbled circuits
	d := make([]int32, cir.totalOutputSize())
	hashOutputWire0 := make([][]byte, cir.totalOutputSize())
	hashOutputWire1 := make([][]byte, cir.totalOutputSize())
	countInt := 0
	outputIndex := cir.countWires - cir.totalOutputSize()
	for i := 0; i < len(cir.outputSize); i++ {
		for j := 0; j < cir.outputSize[i]; j++ {
			d[countInt] = int32(lsb(W[outputIndex+countInt][0]))

			// Generate the following wires are used in dual execution protocol:\
			temphash1 := blake2b.Sum256(W[outputIndex+countInt][0])
			hashOutputWire0[countInt] = temphash1[:]
			temphash2 := blake2b.Sum256(W[outputIndex+countInt][1])
			hashOutputWire1[countInt] = temphash2[:]
			countInt++
		}
	}

	// Encrypt message
	garcir := &GarbleCircuit{
		circuit:    cir,
		E:          e,
		d:          d,
		R:          R,
		outputWire: W[outputIndex:],
	}
	x, err := f(garcir, input)
	if err != nil {
		return nil, nil, err
	}
	return garcir, &GarbleCircuitMessage{
		F:            F,
		D:            d,
		X:            x,
		HOutputWire0: hashOutputWire0,
		HOutputWire1: hashOutputWire1,
		StartCount:   startCount.Bytes(),
	}, nil
}

// Encrytpion/Descrption directly?
// Evaluate: procedure Ev
func (cir *Circuit) EvaluateGarbleCircuit(garbledMsg *GarbleCircuitMessage, input [][]byte) ([]byte, error) {
	count := new(big.Int).SetBytes(garbledMsg.StartCount)
	// Set i in Inputs
	W := make([][]byte, cir.countWires)
	inputSize := cir.totalInputSize()
	for i := 0; i < inputSize; i++ {
		W[i] = input[i]
	}

	indexAndCount := 0
	for i := 0; i < len(cir.gates); i++ {
		g := cir.gates[i]
		switch g.gate {
		case XOR:
			W[g.outputWire[0]] = utils.Xor(W[g.inputWire[0]], W[g.inputWire[1]])
		case AND:
			F := garbledMsg.F[indexAndCount]
			Wa := W[g.inputWire[0]]
			Wb := W[g.inputWire[1]]
			sa := lsb(Wa)
			sb := lsb(Wb)
			tempCount := new(big.Int).Add(count, big1)
			count.Add(count, big2)
			saTGi := utils.BinaryMul(sa, F.TG)
			WGi, _ := h(Wa, tempCount)
			WGi = utils.Xor(WGi, saTGi)
			sbTEiWa := utils.Xor(F.TE, Wa)
			sbTEiWa = utils.BinaryMul(sb, sbTEiWa)
			WEi, _ := h(Wb, count)
			WEi = utils.Xor(WEi, sbTEiWa)
			W[g.outputWire[0]] = utils.Xor(WGi, WEi)
			indexAndCount++
		case INV:
			W[g.outputWire[0]] = W[g.inputWire[0]]
		case EQ:
			W[g.outputWire[0]] = W[g.inputWire[0]]
		default:
			return nil, ErrNONSUPPORTGATE
		}
	}

	// Set the output of the evaluating result.
	Y := make([][]byte, cir.totalOutputSize())
	countIndex := 0
	outputIndex := cir.countWires - cir.totalOutputSize()
	for i := 0; i < len(cir.outputSize); i++ {
		for j := 0; j < cir.outputSize[i]; j++ {
			Y[countIndex] = W[outputIndex+countIndex]
			countIndex++
		}
	}

	// decrypt
	return decrypt(garbledMsg.D, Y), nil
}

// Procedure De
func decrypt(d []int32, Y [][]byte) []uint8 {
	result := make([]uint8, len(d))
	for i := 0; i < len(d); i++ {
		result[i] = uint8(d[i]) ^ lsb(Y[i])
	}
	return result
}

// Get the least-significant bit.
func lsb(input []byte) uint8 {
	return input[len(input)-1] & 1
}

func gbAnd(Wa0, Wa1, Wb0, Wb1 []byte, R []byte, indexj, indexjpai *big.Int) ([]byte, []byte, []byte, error) {
	pa := lsb(Wa0)
	pb := lsb(Wb0)
	// First half gate: T_G := H(Wa^0,j) xor H(Wa^1,j) xor pbR
	pbR := utils.BinaryMul(pb, R)
	temp, err := h(Wa0, indexj)
	if err != nil {
		return nil, nil, nil, err
	}
	temp1, err := h(Wa1, indexj)
	if err != nil {
		return nil, nil, nil, err
	}
	TG := utils.Xor(temp, temp1)
	TG = utils.Xor(TG, pbR)
	// W_G0 = H(Wa0,j) xor paT_G
	WG0 := utils.Xor(temp, utils.BinaryMul(pa, TG))
	// Second half gate: T_E := H(Wb^0,j') xor H(Wb^1,j') xor Wa0
	temp, err = h(Wb0, indexjpai)
	if err != nil {
		return nil, nil, nil, err
	}
	temp1, err = h(Wb1, indexjpai)
	if err != nil {
		return nil, nil, nil, err
	}
	TE := utils.Xor(temp, temp1)
	TE = utils.Xor(TE, Wa0)
	// W_E0 := H(Wb0,j') xor pb(T_E xor W_a0)
	WE0 := utils.Xor(TE, Wa0)
	WE0 = utils.BinaryMul(pb, WE0)
	WE0 = utils.Xor(temp, WE0)
	// combines half gate: W_G0 xor W_G1
	W0 := utils.Xor(WG0, WE0)
	return W0, TG, TE, nil
}

// Section 4.2: MMO(x,i):=E(i,sigma(x)) xor sigma(x), where sigma(x_L||x_R) := x_R xor x_L || x_R.
// ref: garbled Circuit" according to paper: "Better Concrete Security for Half-Gates Garbling
func h(message []byte, index *big.Int) ([]byte, error) {
	informationByte := index.Bytes()
	cipher, err := aes.NewCipher(informationByte)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(message))
	sigmax := sigma(message)
	cipher.Encrypt(ciphertext, sigmax)
	return utils.Xor(ciphertext, sigmax), nil
}

func sigma(input []byte) []byte {
	halfLength := len(input) >> 1
	inputL := input[0:halfLength]
	inputR := input[halfLength:]
	result := utils.Xor(inputL, inputR)
	return append(result, inputL...)
}

// To Hex
func DecodeBristolFashionOutput(binaryOutput []uint8) (string, error) {
	byteSlice, err := utils.BitsToBytes(utils.ReverseByte(binaryOutput))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(byteSlice), nil
}

func SetShaStateBristolInput(state []uint64) ([]uint8, error) {
	if len(state) != 8 {
		return nil, ErrInputSize
	}
	result := make([]uint8, 512)
	for i := 0; i < 8; i++ {
		index := i << 6
		tempInput := utils.ReverseByte(setUint64ToBitSlice(state[i]))
		for j := 0; j < 64; j++ {
			result[index+j] = tempInput[j]
		}
	}
	return utils.ReverseByte(result), nil
}

// TODO: Replace it to nicer method
func setUint64ToBitSlice(input uint64) []uint8 {
	big := new(big.Int).SetUint64(input)
	result := make([]uint8, 64)
	for i := uint8(0); i < 64; i++ {
		result[i] = 0
	}
	for i := 0; i < big.BitLen(); i++ {
		result[i] = uint8(big.Bit(i))
	}
	return result
}

func readText(scanner *bufio.Scanner) string {
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}

func Decrypt(d []int32, Y [][]byte) []uint8 {
	result := make([]uint8, len(d))
	for i := 0; i < len(d); i++ {
		result[i] = uint8(d[i]) ^ lsb(Y[i])
	}
	return result
}
