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
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var (
	SHA512ZeroState = []uint64{0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1,
		0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}
)

var _ = Describe("Bristol fashion evaluate", func() {
	DescribeTable("AES-256 ECB", func(messageString string, keyString string, expected string) {
		// Set the input and the output
		input := make([][]uint8, 2)
		input[0] = make([]uint8, 256)
		input[1] = make([]uint8, 128)
		output := make([][]uint8, 1)
		output[0] = make([]uint8, 128)

		keyBig, _ := new(big.Int).SetString(keyString, 16)
		messageBig, _ := new(big.Int).SetString(messageString, 16)

		// Set key
		for i := 0; i < len(input[0]); i++ {
			input[0][i] = uint8(keyBig.Bit(i))
		}
		//Set message
		for i := 0; i < len(input[1]); i++ {
			input[1][i] = uint8(messageBig.Bit(i))
		}
		// Parse circuit and evaluate it
		cir, err := LoadBristol("bristolFashion/aes_256.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotHex, err := DecodeBristolFashionOutput(got[0])
		Expect(err).Should(BeNil())
		Expect(gotHex == expected).Should(BeTrue())
	},
		// ref: https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES/ECBVarTxt256.rsp
		Entry("Count:128", "ffffffffffffffffffffffffffffffff", "0000000000000000000000000000000000000000000000000000000000000000", "acdace8078a32b1a182bfa4987ca1347"),
		Entry("Count:77", "fffffffffffffffffffc000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "b95ba05b332da61ef63a2b31fcad9879"),
		Entry("Count:63", "ffffffffffffffff0000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "9b58dbfd77fe5aca9cfc190cd1b82d19"),

		// ref: https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES/ECBVarKey256.rsp
		Entry("Count:45", "00000000000000000000000000000000", "fffffffffffc0000000000000000000000000000000000000000000000000000", "82bda118a3ed7af314fa2ccc5c07b761"),
		Entry("Count:126", "00000000000000000000000000000000", "fffffffffffffffffffffffffffffffe00000000000000000000000000000000", "b5f71d4dd9a71fe5d8bc8ba7e6ea3048"),

		// http://www.cryptogrium.com/aes-encryption-online-ecb.html
		Entry("Count:None", "1000000000000000000000000000ABCD", "fffffffffffffffffffffffffffffffe00000000000000000000000000000000", "9ce3b13e4b3f8fe2ee85cec035fb5f0b"),
	)

	DescribeTable("Add 64", func(a, b *big.Int, expected *big.Int) {
		// Set the input and the output
		input := make([][]uint8, 2)
		input[0] = make([]uint8, 64)
		input[1] = make([]uint8, 64)
		output := make([][]uint8, 1)
		output[0] = make([]uint8, 64)

		for i := 0; i < len(input[0]); i++ {
			input[0][i] = uint8(a.Bit(i))
		}
		for i := 0; i < len(input[1]); i++ {
			input[1][i] = uint8(b.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/adder64.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotInt := bitArrayToInt(got[0])
		Expect(gotInt.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("2345 + 17823795 = 17826140", big.NewInt(2345), big.NewInt(17823795), big.NewInt(17826140)),
		Entry("928372 + 746826529925 = 746827458297", big.NewInt(928372), big.NewInt(746826529925), big.NewInt(746827458297)),
	)

	DescribeTable("Add 512 and Mod 512", func(a, b, p string, expected string) {
		// Set the input and the output
		abig, _ := new(big.Int).SetString(a, 10)
		bbig, _ := new(big.Int).SetString(b, 10)
		pbig, _ := new(big.Int).SetString(p, 10)
		inputSereilize := make([]uint8, 1536)

		for i := 0; i < 512; i++ {
			inputSereilize[i] = uint8(abig.Bit(i))
			inputSereilize[512+i] = uint8(bbig.Bit(i))
			inputSereilize[1024+i] = uint8(pbig.Bit(i))
		}

		cir, err := LoadBristol("bristolFashion/ModAdd512.txt")
		Expect(err).Should(BeNil())
		_, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		got, err := cir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		gotInt := bitArrayToInt(got)
		expctedBig, _ := new(big.Int).SetString(expected, 10)
		Expect(gotInt.Cmp(expctedBig) == 0).Should(BeTrue())
	},
		Entry("2345 + 17823795 = 17826140", "2345", "17823795", "999999999", "17826140"),
		Entry("115792089237316195423570985008687907852837564279074904382605163141518161494336 + 3 = 2",
			"115792089237316195423570985008687907852837564279074904382605163141518161494336", "3", "115792089237316195423570985008687907852837564279074904382605163141518161494337", "2"),
		Entry("115792089237316195423570985008687907852837564279074904382605163141518161494336 + 115792089237316195423570985008687907852837564279074904382605163141518161494335 = 115792089237316195423570985008687907852837564279074904382605163141518161494334",
			"115792089237316195423570985008687907852837564279074904382605163141518161494336", "115792089237316195423570985008687907852837564279074904382605163141518161494335", "115792089237316195423570985008687907852837564279074904382605163141518161494337", "115792089237316195423570985008687907852837564279074904382605163141518161494334"),
		Entry("33930247958042109970708014072100655327284160110026365553589579189000489692222 + 0 = 33930247958042109970708014072100655327284160110026365553589579189000489692222",
			"33930247958042109970708014072100655327284160110026365553589579189000489692222", "0", "115792089237316195423570985008687907852837564279074904382605163141518161494337", "33930247958042109970708014072100655327284160110026365553589579189000489692222"),
	)

	DescribeTable("two-shares HMAC", func(a, b, p string, expected string) {
		// Set the input and the output
		input := make([][]uint8, 5)
		input[0] = make([]uint8, 512)
		input[1] = make([]uint8, 512)
		input[2] = make([]uint8, 512)
		input[3] = make([]uint8, 768)
		input[4] = make([]uint8, 512)
		output := make([][]uint8, 1)
		output[0] = make([]uint8, 512)
		abig, _ := new(big.Int).SetString(a, 10)
		bbig, _ := new(big.Int).SetString(b, 10)
		pbig, _ := new(big.Int).SetString(p, 10)
		for i := 0; i < 512; i++ {
			input[0][i] = uint8(abig.Bit(i))
			input[1][i] = uint8(bbig.Bit(i))
			input[2][i] = uint8(pbig.Bit(i))
		}

		indexKey := make([]uint8, 32)
		bigIndexKey := new(big.Int).SetUint64(2147483648)
		for i := 0; i < 32; i++ {
			indexKey[31-i] = uint8(bigIndexKey.Bit(i))
		}
		otherInfo := make([]uint8, 717)
		otherInfo[0] = 1
		countValue := make([]uint8, 11)
		countValue[0] = 1
		countValue[2] = 1
		countValue[5] = 1
		countValue[7] = 1

		zero := make([]uint8, 8)
		otherInfo = append(indexKey, otherInfo...)
		otherInfo = append(otherInfo, countValue...)
		otherInfo = append(otherInfo, zero...)
		input[3] = otherInfo

		var err error
		firstState := []uint64{13391267511336937592, 10825649288538531299, 7302626702636858989,
			5923748789273644036, 17775890146729174739, 5419781481938100878, 584914358309585766, 3624568857826719877}
		input[4], err = SetShaStateBristolInput(firstState)

		cir, err := LoadBristol("bristolFashion/MPCHMAC.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotHex, err := DecodeBristolFashionOutput(got[0])
		Expect(err).Should(BeNil())
		Expect(gotHex == expected).Should(BeTrue())
	},
		// Hash this message: b10bc9b7f619646015cb29d320489a0c63967fe80b077d8218d411c9db01e33e36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363600e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3580000000
		Entry("two-shares", "105366245268346348601399826821003822098691517983742654654633135381666943167200", "85", "115792089237316195423570985008687907852837564279074904382605163141518161494337", "5829666fcf1f7c9e4224c37f502da5ea601f78a9afaa8c58a48d112c7d462896f51e5e370bc15bffa35a4362685e45508ffad7bc5fd48c5c7da1d90800d6b0d7"),
	)

	DescribeTable("two-subseed MPCSEED", func(seedstring, b, p string, expected string) {
		// Set the input and the output
		seedByte, _ := hex.DecodeString(seedstring)
		seed := utils.BytesToBits(seedByte)
		input := make([][]uint8, 7)
		input[0] = seed[0:256]
		input[1] = make([]uint8, 512)
		input[2] = seed[256:512]
		input[3] = make([]uint8, 512)
		input[4] = make([]uint8, 512)
		input[5] = make([]uint8, 512)
		input[6] = make([]uint8, 512)
		output := make([][]uint8, 1)
		output[0] = make([]uint8, 768)
		randomValue, _ := new(big.Int).SetString(b, 10)
		pbig, _ := new(big.Int).SetString(p, 10)
		for i := 0; i < randomValue.BitLen(); i++ {
			input[1][i] = uint8(randomValue.Bit(i))
		}
		for i := 0; i < pbig.BitLen(); i++ {
			input[4][i] = uint8(pbig.Bit(i))
		}
		otherInfo := make([]uint8, 501)
		otherInfo[0] = 1
		countValue := make([]uint8, 11)
		countValue[0] = 1
		countValue[1] = 1

		otherInfo = append(otherInfo, countValue...)
		input[3] = otherInfo

		inputResult := input[0]
		inputResult = append(inputResult, input[2]...)
		inputResult = append(inputResult, input[3]...)

		var err error
		firstState := []uint64{3326739937957255283, 8688772341620556602, 15932180217903289146,
			16593632695233548967, 18143991045780064928, 11715845138021987934, 18298647192286487112,
			3456966267567238595}
		input[5], err = SetShaStateBristolInput(firstState)

		firstStateOther := []uint64{13534015809423056317, 15928041516761626561, 16131116959625208868,
			2955168835985126220, 11749762402537216508, 7612603733104932751, 360328074546165396,
			17786688585256325943}
		input[6], err = SetShaStateBristolInput(firstStateOther)

		cir, err := LoadBristol("bristolFashion/MPCSEED.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotHex, err := DecodeBristolFashionOutput(got[0])
		Expect(err).Should(BeNil())

		Expect(gotHex[0:64] == expected[64:]).Should(BeTrue())
		share1, _ := new(big.Int).SetString(gotHex[64:], 16)
		privateKey := new(big.Int).Sub(share1, randomValue)
		privateKey.Mod(privateKey, pbig)
		expectedPrivateKey, _ := new(big.Int).SetString(expected[0:64], 16)
		Expect(privateKey.Cmp(expectedPrivateKey) == 0).Should(BeTrue())
	},
		Entry("case1:", "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "115792089237316195423570985008687907852837564279074904382605163141518161494335", "115792089237316195423570985008687907852837564279074904382605163141518161494337", "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"),
	)

	DescribeTable("sha256", func(input, expected string) {
		inputSereilize := make([]uint8, 512)
		inputBig, _ := new(big.Int).SetString(input, 16)
		H0 := setHexToIntSlice("5be0cd19", 32)
		H0 = append(H0, setHexToIntSlice("1f83d9ab", 32)...)
		H0 = append(H0, setHexToIntSlice("9b05688c", 32)...)
		H0 = append(H0, setHexToIntSlice("510e527f", 32)...)
		H0 = append(H0, setHexToIntSlice("a54ff53a", 32)...)
		H0 = append(H0, setHexToIntSlice("3c6ef372", 32)...)
		H0 = append(H0, setHexToIntSlice("bb67ae85", 32)...)
		H0 = append(H0, setHexToIntSlice("6a09e667", 32)...)
		for i := 0; i < inputBig.BitLen(); i++ {
			inputSereilize[i] = uint8(inputBig.Bit(i))
		}
		inputSereilize = append(inputSereilize, H0...)

		cir, err := LoadBristol("bristolFashion/sha256.txt")
		Expect(err).Should(BeNil())
		_, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		got, err := cir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		gotHex, err := DecodeBristolFashionOutput(got)
		Expect(err).Should(BeNil())
		Expect(gotHex == expected).Should(BeTrue())
	},
		Entry("test case1:", "61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
		Entry("test case2:", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "fc99a2df88f42a7a7bb9d18033cdc6a20256755f9d5b9a5044a9cc315abe84a7"),
	)

	DescribeTable("Garble: AES-256 ECB", func(messageString string, keyString string, expected string) {
		keyBig, _ := new(big.Int).SetString(keyString, 16)
		messageBig, _ := new(big.Int).SetString(messageString, 16)
		inputSereilize := make([]uint8, 384)
		for i := 0; i < 256; i++ {
			inputSereilize[i] = uint8(keyBig.Bit(i))
		}
		for i := 0; i < 128; i++ {
			inputSereilize[i+256] = uint8(messageBig.Bit(i))
		}
		// Parse circuit and evaluate it
		cir, err := LoadBristol("bristolFashion/aes_256.txt")
		Expect(err).Should(BeNil())
		_, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		got, err := cir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		gotHex, err := DecodeBristolFashionOutput(got)
		Expect(err).Should(BeNil())
		Expect(gotHex == expected).Should(BeTrue())
	},
		// ref: https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES/ECBVarTxt256.rsp
		Entry("Count:128", "ffffffffffffffffffffffffffffffff", "0000000000000000000000000000000000000000000000000000000000000000", "acdace8078a32b1a182bfa4987ca1347"),
		Entry("Count:77", "fffffffffffffffffffc000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "b95ba05b332da61ef63a2b31fcad9879"),
		Entry("Count:63", "ffffffffffffffff0000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "9b58dbfd77fe5aca9cfc190cd1b82d19"),

		// ref: https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES/ECBVarKey256.rsp
		Entry("Count:45", "00000000000000000000000000000000", "fffffffffffc0000000000000000000000000000000000000000000000000000", "82bda118a3ed7af314fa2ccc5c07b761"),
		Entry("Count:126", "00000000000000000000000000000000", "fffffffffffffffffffffffffffffffe00000000000000000000000000000000", "b5f71d4dd9a71fe5d8bc8ba7e6ea3048"),

		// http://www.cryptogrium.com/aes-encryption-online-ecb.html
		Entry("Count:None", "1000000000000000000000000000ABCD", "fffffffffffffffffffffffffffffffe00000000000000000000000000000000", "9ce3b13e4b3f8fe2ee85cec035fb5f0b"),
	)
})

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

func setHexToIntSlice(input string, exptected uint8) []uint8 {
	big, _ := new(big.Int).SetString(input, 16)
	result := make([]uint8, exptected)
	for i := uint8(0); i < exptected; i++ {
		result[i] = 0
	}
	for i := 0; i < big.BitLen(); i++ {
		result[i] = uint8(big.Bit(i))
	}
	return result
}

func TestCircuit(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Circuit Test")
}

// Just test use. To test the result of parsing is correct.
func (cir *Circuit) evaluate(input [][]uint8) ([][]uint8, error) {
	wires := make([]uint8, cir.countWires)
	// for i := 0; i < len(wires); i++ {
	// 	wires[i] = -1
	// }
	// Set the input
	count := 0
	for i := 0; i < len(input); i++ {
		for j := 0; j < len(input[i]); j++ {
			wires[count] = input[i][j]
			count++
		}
	}

	// Evaluate booling Circuit
	for i := 0; i < len(cir.gates); i++ {
		tempGate := cir.gates[i]
		if tempGate.gate == AND {
			wires[tempGate.outputWire[0]] = wires[tempGate.inputWire[0]] & wires[tempGate.inputWire[1]]
			continue
		}
		if tempGate.gate == XOR {
			wires[tempGate.outputWire[0]] = wires[tempGate.inputWire[0]] ^ wires[tempGate.inputWire[1]]
			continue
		}
		if tempGate.gate == INV {
			wires[tempGate.outputWire[0]] = 1 - wires[tempGate.inputWire[0]]
			continue
		}
		if tempGate.gate == EQ {
			wires[tempGate.outputWire[0]] = wires[tempGate.inputWire[0]]
			continue
		}
		return nil, ErrNOIMPLEMENT
	}

	// Set the output
	output := make([][]uint8, len(cir.outputSize))
	count = cir.countWires
	for i := 0; i < len(output); i++ {
		count = count - cir.outputSize[i]
	}
	for i := 0; i < len(output); i++ {
		temp := make([]uint8, cir.outputSize[i])
		for j := 0; j < len(temp); j++ {
			temp[j] = wires[count]
			count++
		}
		output[i] = temp
	}

	return output, nil
}
