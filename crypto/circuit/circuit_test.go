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

	curveN, _ = new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)
	bit80     = new(big.Int).Lsh(big1, 80)
	bit33     = new(big.Int).Lsh(big1, 33)
	bit30     = new(big.Int).Lsh(big1, 30)
	big0      = big.NewInt(0)
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

	DescribeTable("Add 64", func(a, b *big.Int) {
		// Set the input and the output
		input := make([][]uint8, 2)
		input[0] = make([]uint8, 64)
		input[1] = make([]uint8, 64)

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
		expected := new(big.Int).Add(a, b)
		Expect(gotInt.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("0 + 1 = 1", big.NewInt(0), big1),
		Entry("2^63-135783737373 + 2^63-2", new(big.Int).Sub(new(big.Int).Lsh(big1, 63), big.NewInt(135783737373)), new(big.Int).Sub(new(big.Int).Lsh(big1, 63), big.NewInt(2))),
		Entry("928372 + 746826529925 = 746827458297", big.NewInt(928372), big.NewInt(746826529925)),
		Entry("2^63 + 0 = 2^63", new(big.Int).Lsh(big1, 63), big.NewInt(0)),
	)

	DescribeTable("Add 256", func(a, b *big.Int) {
		// Set the input and the output
		input := make([][]uint8, 2)
		input[0] = make([]uint8, 256)
		input[1] = make([]uint8, 256)

		for i := 0; i < len(input[0]); i++ {
			input[0][i] = uint8(a.Bit(i))
		}
		for i := 0; i < len(input[1]); i++ {
			input[1][i] = uint8(b.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/adder256.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotInt := bitArrayToInt(got[0])
		expected := new(big.Int).Add(a, b)
		Expect(gotInt.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("2^253-135783737373 + 2^250-2", new(big.Int).Sub(new(big.Int).Lsh(big1, 253), big.NewInt(135783737373)), new(big.Int).Sub(new(big.Int).Lsh(big1, 250), big.NewInt(2))),
		Entry("928372 + 746826529925 = 746827458297", big.NewInt(928372), big.NewInt(746826529925)),
		Entry("2^255-135783737373 + 2^255-2", new(big.Int).Sub(new(big.Int).Lsh(big1, 255), big.NewInt(135783737373)), new(big.Int).Sub(new(big.Int).Lsh(big1, 255), big.NewInt(2))),
		Entry("2^256-1 + 2^256-1", new(big.Int).Sub(new(big.Int).Lsh(big1, 256), big.NewInt(1)), new(big.Int).Sub(new(big.Int).Lsh(big1, 256), big.NewInt(1))),
	)

	DescribeTable("Mul 256", func(a, b *big.Int) {
		// Set the input and the output
		input := make([][]uint8, 2)
		input[0] = make([]uint8, 256)
		input[1] = make([]uint8, 256)

		for i := 0; i < len(input[0]); i++ {
			input[0][i] = uint8(a.Bit(i))
		}
		for i := 0; i < len(input[1]); i++ {
			input[1][i] = uint8(b.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/mul256.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotInt := bitArrayToInt(got[0])
		expected := new(big.Int).Mul(a, b)
		Expect(gotInt.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("2^253-135783737373 * 2^250-2", new(big.Int).Sub(new(big.Int).Lsh(big1, 253), big.NewInt(135783737373)), new(big.Int).Sub(new(big.Int).Lsh(big1, 250), big.NewInt(2))),
		Entry("0 *63", big.NewInt(0), big.NewInt(63)),
		Entry("1 *6283479234792384793", big.NewInt(1), big.NewInt(6283479234792384793)),
		Entry("2^255-135783737373 * 2^255-2", new(big.Int).Sub(new(big.Int).Lsh(big1, 255), big.NewInt(135783737373)), new(big.Int).Sub(new(big.Int).Lsh(big1, 255), big.NewInt(2))),
		Entry("2^256-1 * 2^256-1", new(big.Int).Sub(new(big.Int).Lsh(big1, 256), big.NewInt(1)), new(big.Int).Sub(new(big.Int).Lsh(big1, 256), big.NewInt(1))),
		Entry("2^256-892374928749 * 2^256-9283749279", new(big.Int).Sub(new(big.Int).Lsh(big1, 256), big.NewInt(892374928749)), new(big.Int).Sub(new(big.Int).Lsh(big1, 256), big.NewInt(9283749279))),
		Entry("2^254-1 + 2^63-1", new(big.Int).Sub(new(big.Int).Lsh(big1, 254), big.NewInt(1)), new(big.Int).Sub(new(big.Int).Lsh(big1, 63), big.NewInt(1))),
	)

	DescribeTable("Mul 80*256", func() {
		// Set the input and the output
		input := make([][]uint8, 2)
		input[0] = make([]uint8, 256)
		input[1] = make([]uint8, 80)

		a, _ := utils.RandomPositiveInt(curveN)
		b, _ := utils.RandomPositiveInt(bit80)
		for i := 0; i < len(input[0]); i++ {
			input[0][i] = uint8(a.Bit(i))
		}
		for i := 0; i < len(input[1]); i++ {
			input[1][i] = uint8(b.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/256mul80.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotInt := bitArrayToInt(got[0])
		expected := new(big.Int).Mul(a, b)
		Expect(gotInt.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("Random test"),
	)

	// teset
	DescribeTable("minus 80*256", func() {
		// Set the input and the output
		input := make([][]uint8, 2)
		input[0] = make([]uint8, 256)
		input[1] = make([]uint8, 256)

		a := curveN
		b := curveN
		for i := 0; i < len(input[0]); i++ {
			input[0][i] = uint8(a.Bit(i))
		}
		for i := 0; i < len(input[1]); i++ {
			input[1][i] = uint8(b.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/minus.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotInt := bitArrayToInt(got[0])
		expected := new(big.Int).Sub(a, b)
		Expect(gotInt.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("Random test"),
	)

	DescribeTable("mod q (288 bit)", func(aString string) {
		// Set the input and the output
		input := make([][]uint8, 1)
		input[0] = make([]uint8, 287)

		a, _ := new(big.Int).SetString(aString, 10)
		if a.Cmp(big0) < 0 {
			a, _ = utils.RandomInt(new(big.Int).Lsh(big1, 287))
		}

		for i := 0; i < len(input[0]); i++ {
			input[0][i] = uint8(a.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/modq287.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotInt := bitArrayToInt(got[0])
		expected := new(big.Int).Mod(a, curveN)
		Expect(gotInt.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("2^256-1 +2^259+2^286", "124330810144575463674691320848844075103305208378766791350881070578408130324351510642687"),
		Entry("Random test", "-1"),
	)

	DescribeTable("mod q (258 bit)", func(aString string) {
		// Set the input and the output
		input := make([][]uint8, 1)
		input[0] = make([]uint8, 258)

		a, _ := new(big.Int).SetString(aString, 10)
		if a.Cmp(big0) < 0 {
			a, _ = utils.RandomInt(new(big.Int).Lsh(big1, 258))
		}

		for i := 0; i < len(input[0]); i++ {
			input[0][i] = uint8(a.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/modq258.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		gotInt := bitArrayToInt(got[0])
		expected := new(big.Int).Mod(a, curveN)
		Expect(gotInt.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("2^256-1 +2^259+2^286", "463168356949264781694283940034751631412647518275996596500977915165257550414145"),
		Entry("Random test", "-1"),
	)

	// Warn: if the bitLength of a+b = 513 then this function is failure.
	DescribeTable("Add 512 and Mod 512", func(a, b, p string) {
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
		garcir, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		evaluation, err := garcir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		got, err := utils.BitsToBytes(utils.ReverseByte(Decrypt(garMsg.GetD(), evaluation)))
		gotInt := new(big.Int).SetBytes(got)
		gotInt.Mod(gotInt, pbig)
		expctedBig := new(big.Int).Add(abig, bbig)
		expctedBig.Mod(expctedBig, pbig)

		Expect(gotInt.Cmp(expctedBig) == 0).Should(BeTrue())
	},
		Entry("2345 + 17823795 = 17826140", "2345", "17823795", "999999999"),
		Entry("115792089237316195423570985008687907852837564279074904382605163141518161494336 + 3 = 2",
			"115792089237316195423570985008687907852837564279074904382605163141518161494336", "115792089237316195423570985008687907852837564279074904382605163141518161494336", "115792089237316195423570985008687907852837564279074904382605163141518161494337"),
		Entry("115792089237316195423570985008687907852837564279074904382605163141518161494336 + 115792089237316195423570985008687907852837564279074904382605163141518161494335 = 115792089237316195423570985008687907852837564279074904382605163141518161494334",
			"115792089237316195423570985008687907852837564279074904382605163141518161494336", "115792089237316195423570985008687907852837564279074904382605163141518161494335", "115792089237316195423570985008687907852837564279074904382605163141518161494337"),
		Entry("33930247958042109970708014072100655327284160110026365553589579189000489692222 + 0 = 33930247958042109970708014072100655327284160110026365553589579189000489692222",
			"33930247958042109970708014072100655327284160110026365553589579189000489692222", "0", "115792089237316195423570985008687907852837564279074904382605163141518161494337"),
		Entry("115792089237316195423570985008687907852837564279074904382605163141518161494999 + 0 = 33930247958042109970708014072100655327284160110026365553589579189000489692222",
			"115792089237316195423570985008687907852837564279074904382605163141518161494999", "115792089237316195423570985008687907852837564279074904382605163141518161494999", "115792089237316195423570985008687907852837564279074904382605163141518161494337"),
	)

	DescribeTable("Child Key Generation", func(a, b string, expected string) {
		// Set the input and the output
		// Input:  hashotherInfo, hashstate, share1, m1, r1, n1, share2, m2, r2, n2
		input := make([][]uint8, 10)
		input[0] = make([]uint8, 768)
		input[1] = make([]uint8, 512)
		input[2] = make([]uint8, 256)
		input[3] = make([]uint8, 256)
		input[4] = make([]uint8, 256)
		input[5] = make([]uint8, 33)
		input[6] = make([]uint8, 256)
		input[7] = make([]uint8, 256)
		input[8] = make([]uint8, 256)
		input[9] = make([]uint8, 33)

		r2, _ := utils.RandomPositiveInt(curveN)
		r1, _ := utils.RandomPositiveInt(curveN)
		n1, _ := utils.RandomPositiveInt(bit33)
		n2, _ := utils.RandomPositiveInt(bit33)
		m1, _ := utils.RandomPositiveInt(curveN)
		m2, _ := utils.RandomPositiveInt(curveN)
		s1, _ := new(big.Int).SetString(a, 10)
		s1.Sub(s1, m1)
		s1.Mod(s1, curveN)
		s2, _ := new(big.Int).SetString(b, 10)
		s2.Sub(s2, m2)
		s2.Mod(s2, curveN)
		for i := 0; i < s1.BitLen(); i++ {
			input[2][i] = uint8(s1.Bit(i))
		}
		for i := 0; i < r1.BitLen(); i++ {
			input[4][i] = uint8(r1.Bit(i))
		}
		for i := 0; i < m1.BitLen(); i++ {
			input[3][i] = uint8(m1.Bit(i))
		}
		for i := 0; i < s2.BitLen(); i++ {
			input[6][i] = uint8(s2.Bit(i))
		}
		for i := 0; i < m2.BitLen(); i++ {
			input[7][i] = uint8(m2.Bit(i))
		}
		for i := 0; i < r2.BitLen(); i++ {
			input[8][i] = uint8(r2.Bit(i))
		}
		for i := 0; i < n2.BitLen(); i++ {
			input[9][i] = uint8(n2.Bit(i))
		}
		for i := 0; i < n1.BitLen(); i++ {
			input[5][i] = uint8(n1.Bit(i))
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
		input[0] = otherInfo

		var err error
		firstState := []uint64{13391267511336937592, 10825649288538531299, 7302626702636858989,
			5923748789273644036, 17775890146729174739, 5419781481938100878, 584914358309585766, 3624568857826719877}
		input[1], err = SetShaStateBristolInput(firstState)

		cir, err := LoadBristol("bristolFashion/ckd.txt")
		Expect(err).Should(BeNil())
		got, err := cir.evaluate(input)
		Expect(err).Should(BeNil())
		n1Addn2 := new(big.Int).Add(n1, n2)
		getN1AddN2 := bitArrayToInt(got[0][768:])
		Expect(n1Addn2.Cmp(getN1AddN2) == 0).Should(BeTrue())

		// output: [0:512]: I, [512:768]: s1+m1+s2+m2+r1n2+n1r2 mod q, and [768:]: n1+n2
		compareValue := new(big.Int).Add(s1, m1)
		compareValue.Add(compareValue, s2)
		compareValue.Add(compareValue, m2)
		compareValue.Add(compareValue, new(big.Int).Mul(r1, n2))
		compareValue.Add(compareValue, new(big.Int).Mul(r2, n1))
		compareValue.Mod(compareValue, curveN)
		expecteValueHex, err := DecodeBristolFashionOutput(got[0][512:768])
		expecteValue, _ := new(big.Int).SetString(expecteValueHex, 16)
		Expect(err).Should(BeNil())
		Expect(expecteValue.Cmp(compareValue) == 0).Should(BeTrue())

		I, err := DecodeBristolFashionOutput(got[0][0:512])
		Expect(I == expected).Should(BeTrue())
	},
		// Hash this message: b10bc9b7f619646015cb29d320489a0c63967fe80b077d8218d411c9db01e33e36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363600e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3580000000
		Entry("two-shares", "105366245268346348601399826821003822098691517983742654654633135381666943167200", "85", "5829666fcf1f7c9e4224c37f502da5ea601f78a9afaa8c58a48d112c7d462896f51e5e370bc15bffa35a4362685e45508ffad7bc5fd48c5c7da1d90800d6b0d7"),
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
		garcir, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		evaluation, err := garcir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		got := Decrypt(garMsg.GetD(), evaluation)
		gotHex, err := DecodeBristolFashionOutput(got)
		Expect(err).Should(BeNil())
		Expect(gotHex == expected).Should(BeTrue())
	},
		Entry("test case1:", "61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
		Entry("test case2:", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "fc99a2df88f42a7a7bb9d18033cdc6a20256755f9d5b9a5044a9cc315abe84a7"),
	)

	DescribeTable("sha512", func(expected string) {
		input := make([][]uint8, 3)

		seedstring := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
		seedByte, _ := hex.DecodeString(seedstring)
		seed := utils.BytesToBits(seedByte)

		input[0] = seed[0:]
		otherInfo := make([]uint8, 501)
		otherInfo[0] = 1
		countValue := make([]uint8, 11)
		countValue[0] = 1
		countValue[1] = 1
		otherInfo = append(otherInfo, countValue...)
		input[1] = otherInfo

		var err error
		firstState := []uint64{3326739937957255283, 8688772341620556602, 15932180217903289146,
			16593632695233548967, 18143991045780064928, 11715845138021987934, 18298647192286487112,
			3456966267567238595}
		input[2], err = SetShaStateBristolInput(firstState)
		Expect(err).Should(BeNil())
		inputSereilize := append(input[0], input[1]...)
		inputSereilize = utils.ReverseByte(inputSereilize)
		inputSereilize = append(inputSereilize, input[2]...)

		cir, err := LoadBristol("bristolFashion/sha512.txt")
		Expect(err).Should(BeNil())
		garcir, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		evaluation, err := garcir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		got := Decrypt(garMsg.GetD(), evaluation)
		gotHex, err := DecodeBristolFashionOutput(got)
		Expect(err).Should(BeNil())
		Expect(gotHex == expected).Should(BeTrue())
	},
		Entry("test case1:", "e87a404a9eb3b31800ae36105a5963eab56dc2cace3a8756791dcb8b78f7a8f393b2cb6a2db3c43d4d90a3326611d78fb4b18244bc465b4c4b93ec09ecdc3a19"),
	)

	DescribeTable("CKD:ckdArithPart", func(expected string) {
		// input: seed1, r1, seed2, n2, otherInfo, hashState1, hashState2
		input := make([][]uint8, 8)
		input[0] = make([]uint8, 256)
		input[1] = make([]uint8, 256)
		input[2] = make([]uint8, 256)
		input[3] = make([]uint8, 33)
		input[4] = make([]uint8, 256)
		input[5] = make([]uint8, 256)
		input[6] = make([]uint8, 256)
		input[7] = make([]uint8, 33)

		r2, _ := utils.RandomPositiveInt(curveN)
		r1, _ := utils.RandomPositiveInt(curveN)
		n1, _ := utils.RandomPositiveInt(bit33)
		n2, _ := utils.RandomPositiveInt(bit33)
		s1, _ := utils.RandomPositiveInt(curveN)
		s2, _ := utils.RandomPositiveInt(curveN)
		m1, _ := utils.RandomPositiveInt(curveN)
		m2, _ := utils.RandomPositiveInt(curveN)
		for i := 0; i < s1.BitLen(); i++ {
			input[0][i] = uint8(s1.Bit(i))
		}
		for i := 0; i < r1.BitLen(); i++ {
			input[2][i] = uint8(r1.Bit(i))
		}
		for i := 0; i < m1.BitLen(); i++ {
			input[1][i] = uint8(m1.Bit(i))
		}
		for i := 0; i < s2.BitLen(); i++ {
			input[4][i] = uint8(s2.Bit(i))
		}
		for i := 0; i < m2.BitLen(); i++ {
			input[5][i] = uint8(m2.Bit(i))
		}
		for i := 0; i < r2.BitLen(); i++ {
			input[6][i] = uint8(r2.Bit(i))
		}
		for i := 0; i < n2.BitLen(); i++ {
			input[7][i] = uint8(n2.Bit(i))
		}
		for i := 0; i < n1.BitLen(); i++ {
			input[3][i] = uint8(n1.Bit(i))
		}

		inputSereilize := input[0]
		inputSereilize = append(inputSereilize, input[1]...)
		inputSereilize = append(inputSereilize, input[2]...)
		inputSereilize = append(inputSereilize, input[3]...)
		inputSereilize = append(inputSereilize, input[4]...)
		inputSereilize = append(inputSereilize, input[5]...)
		inputSereilize = append(inputSereilize, input[6]...)
		inputSereilize = append(inputSereilize, input[7]...)

		cir, err := LoadBristol("bristolFashion/ckdArithPart.txt")
		Expect(err).Should(BeNil())
		garcir, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		evaluation, err := garcir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		// output: [0:256]:I_L+r1n2, [256:257]: isSmall
		got := Decrypt(garMsg.GetD(), evaluation)
		gotHex, err := DecodeBristolFashionOutput(got[0:256])
		mAddNModq, _ := new(big.Int).SetString(gotHex, 16)
		expecteds1m1Adds2m2 := new(big.Int).Add(new(big.Int).Add(s1, m1), new(big.Int).Add(s2, m2))
		expecteds1m1Adds2m2.Mod(expecteds1m1Adds2m2, curveN)
		expectedComparePart := new(big.Int).Add(new(big.Int).Mul(r1, n2), new(big.Int).Mul(r2, n1))
		expectedComparePart.Add(expectedComparePart, expecteds1m1Adds2m2)
		expectedComparePart.Mod(expectedComparePart, curveN)
		Expect(expectedComparePart.Cmp(mAddNModq) == 0).Should(BeTrue())
		gotHex, err = DecodeBristolFashionOutput(got[256:512])
		gots1m1Adds2m2, _ := new(big.Int).SetString(gotHex, 16)
		Expect(expecteds1m1Adds2m2.Cmp(gots1m1Adds2m2) == 0).Should(BeTrue())

		n1Addn2 := new(big.Int).Add(n1, n2)
		getN1AddN2 := bitArrayToInt((Decrypt(garMsg.GetD(), evaluation))[0:])
		Expect(n1Addn2.Cmp(getN1AddN2) == 0).Should(BeTrue())

	},
		Entry("test case1:", "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"),
	)

	DescribeTable("MKG:aux", func(expected string) {
		seedstring := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
		seedByte, _ := hex.DecodeString(seedstring)
		seed := utils.BytesToBits(seedByte)
		seed2, _ := utils.GenRandomBytes(64)
		seed2 = utils.BytesToBits(seed2)
		seed1 := utils.Xor(seed2, seed)
		// input: seed1, r1, seed2, n2, otherInfo, hashState1, hashState2
		input := make([][]uint8, 7)
		input[0] = seed1[0:]
		input[1] = make([]uint8, 256)
		input[2] = seed2[0:]
		input[3] = make([]uint8, 33)
		input[4] = make([]uint8, 512)
		input[5] = make([]uint8, 512)
		input[6] = make([]uint8, 512)

		var err error
		firstState := []uint64{3326739937957255283, 8688772341620556602, 15932180217903289146,
			16593632695233548967, 18143991045780064928, 11715845138021987934, 18298647192286487112,
			3456966267567238595}
		input[5], err = SetShaStateBristolInput(firstState)
		firstStateOther := []uint64{13534015809423056317, 15928041516761626561, 16131116959625208868,
			2955168835985126220, 11749762402537216508, 7612603733104932751, 360328074546165396,
			17786688585256325943}
		input[6], err = SetShaStateBristolInput(firstStateOther)
		otherInfo := make([]uint8, 501)
		otherInfo[0] = 1
		countValue := make([]uint8, 11)
		countValue[0] = 1
		countValue[1] = 1
		otherInfo = append(otherInfo, countValue...)
		input[4] = otherInfo

		r2, _ := utils.RandomPositiveInt(curveN)
		n1, _ := utils.RandomPositiveInt(bit33)
		for i := 0; i < r2.BitLen(); i++ {
			input[1][i] = uint8(r2.Bit(i))
		}
		for i := 0; i < n1.BitLen(); i++ {
			input[3][i] = uint8(n1.Bit(i))
		}

		inputSereilize := input[0]
		inputSereilize = append(inputSereilize, input[1]...)
		inputSereilize = append(inputSereilize, input[2]...)
		inputSereilize = append(inputSereilize, input[3]...)
		inputSereilize = append(inputSereilize, input[4]...)
		inputSereilize = append(inputSereilize, input[5]...)
		inputSereilize = append(inputSereilize, input[6]...)
		// inputSereilize = append(inputSereilize, input[7]...)

		cir, err := LoadBristol("bristolFashion/aux.txt")
		Expect(err).Should(BeNil())
		garcir, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		evaluation, err := garcir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		// output: [0:256]:I_L+r1n2, [256:257]: isSmall
		got := Decrypt(garMsg.GetD(), evaluation)
		gotHex, err := DecodeBristolFashionOutput(got[0:256])
		Expect(err).Should(BeNil())
		isCorrectIL := got[256:257][0]
		Expect(isCorrectIL == 1).Should(BeTrue())
		share1, _ := new(big.Int).SetString(gotHex, 16)
		privateKey := new(big.Int).Sub(share1, new(big.Int).Mul(r2, n1))
		privateKey.Mod(privateKey, curveN)
		expectedPrivateKey, _ := new(big.Int).SetString(expected[0:64], 16)
		Expect(privateKey.Cmp(expectedPrivateKey) == 0).Should(BeTrue())
	},
		Entry("test case1:", "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"),
	)

	DescribeTable("MKG", func(expected string) {
		seedstring := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
		seedByte, _ := hex.DecodeString(seedstring)
		seed := utils.BytesToBits(seedByte)
		// input: seed1, r1, n1, seed2, r2, n2, hmacotherInfo, hashState1, hashState2
		input := make([][]uint8, 9)
		input[0] = seed[:512]
		input[1] = make([]uint8, 256)
		input[2] = make([]uint8, 33)
		input[3] = make([]uint8, 512)
		input[4] = make([]uint8, 256)
		input[5] = make([]uint8, 33)
		input[6] = make([]uint8, 512)
		input[7] = make([]uint8, 512)
		input[8] = make([]uint8, 512)
		var err error
		firstState := []uint64{3326739937957255283, 8688772341620556602, 15932180217903289146,
			16593632695233548967, 18143991045780064928, 11715845138021987934, 18298647192286487112,
			3456966267567238595}
		input[7], err = SetShaStateBristolInput(firstState)

		firstStateOther := []uint64{13534015809423056317, 15928041516761626561, 16131116959625208868,
			2955168835985126220, 11749762402537216508, 7612603733104932751, 360328074546165396,
			17786688585256325943}
		input[8], err = SetShaStateBristolInput(firstStateOther)
		otherInfo := make([]uint8, 501)
		otherInfo[0] = 1
		countValue := make([]uint8, 11)
		countValue[0] = 1
		countValue[1] = 1
		otherInfo = append(otherInfo, countValue...)
		input[6] = otherInfo

		r2, _ := utils.RandomPositiveInt(curveN)
		n1, _ := utils.RandomPositiveInt(bit33)
		for i := 0; i < r2.BitLen(); i++ {
			input[4][i] = uint8(r2.Bit(i))
		}
		for i := 0; i < n1.BitLen(); i++ {
			input[2][i] = uint8(n1.Bit(i))
		}

		r1, _ := utils.RandomPositiveInt(curveN)
		n2, _ := utils.RandomPositiveInt(bit33)
		for i := 0; i < r1.BitLen(); i++ {
			input[1][i] = uint8(r1.Bit(i))
		}
		for i := 0; i < n2.BitLen(); i++ {
			input[5][i] = uint8(n2.Bit(i))
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

		cir, err := LoadBristol("bristolFashion/seed.txt")
		Expect(err).Should(BeNil())
		garcir, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		evaluation, err := garcir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		// Output: [0:31]: n1+n2 mod q, [31:287]: I_L+n1r2+n2r1 mod q, [287:]: I_R
		got := Decrypt(garMsg.GetD(), evaluation)
		gotN := bitArrayToInt((Decrypt(garMsg.GetD(), evaluation))[0:34])
		n := new(big.Int).Add(n1, n2)
		Expect(n.Cmp(gotN) == 0).Should(BeTrue())

		gotInt, err := DecodeBristolFashionOutput(got[34:290])
		Expect(err).Should(BeNil())
		gotShare, _ := new(big.Int).SetString(gotInt, 16)
		privateKey := new(big.Int).Sub(gotShare, new(big.Int).Mul(r2, n1))
		privateKey = new(big.Int).Sub(privateKey, new(big.Int).Mul(r1, n2))
		privateKey.Mod(privateKey, curveN)
		expectedPrivateKey, _ := new(big.Int).SetString(expected[0:64], 16)
		Expect(privateKey.Cmp(expectedPrivateKey) == 0).Should(BeTrue())

		gotHex, err := DecodeBristolFashionOutput(got[290:])
		Expect(err).Should(BeNil())
		Expect(gotHex == expected[64:]).Should(BeTrue())
	},
		Entry("test case1:", "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"),
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
		garcir, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		evaluation, err := garcir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).Should(BeNil())
		got := Decrypt(garMsg.GetD(), evaluation)
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

	Context("ScalMulFieldElement()", func() {
		It("LoadBristol(): Does not exist path", func() {
			_, err := LoadBristol("MarkGOGO")
			Expect(err).ShouldNot(BeNil())
		})

		It("LoadBristol(): Nonimplement gate", func() {
			_, err := LoadBristol("bristolFashion/test.txt")
			Expect(err).ShouldNot(BeNil())
		})
	})

	It("LoadBristol(): Nonimplement gate", func() {
		abig, _ := new(big.Int).SetString("1", 10)
		bbig, _ := new(big.Int).SetString("2", 10)
		pbig, _ := new(big.Int).SetString("100", 10)
		inputSereilize := make([]uint8, 1536)
		for i := 0; i < 512; i++ {
			inputSereilize[i] = uint8(abig.Bit(i))
			inputSereilize[512+i] = uint8(bbig.Bit(i))
			inputSereilize[1024+i] = uint8(pbig.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/ModAdd512.txt")
		Expect(err).Should(BeNil())
		garcir, garMsg, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		garcir.circuit.gates[0].gate = "WOW"
		_, err = garcir.EvaluateGarbleCircuit(garMsg, garMsg.X)
		Expect(err).ShouldNot(BeNil())
	})

	It("GenerateGarbleWire()", func() {
		abig, _ := new(big.Int).SetString("1", 10)
		bbig, _ := new(big.Int).SetString("2", 10)
		pbig, _ := new(big.Int).SetString("100", 10)
		inputSereilize := make([]uint8, 1536)
		for i := 0; i < 512; i++ {
			inputSereilize[i] = uint8(abig.Bit(i))
			inputSereilize[512+i] = uint8(bbig.Bit(i))
			inputSereilize[1024+i] = uint8(pbig.Bit(i))
		}
		cir, err := LoadBristol("bristolFashion/ModAdd512.txt")
		Expect(err).Should(BeNil())
		garcir, _, err := cir.Garbled(128, inputSereilize, EncryptFunc(0))
		Expect(err).Should(BeNil())
		w1, w2 := garcir.GenerateGarbleWire(0, 10)
		Expect(len(w1)).Should(BeNumerically("==", 10))
		Expect(len(w2)).Should(BeNumerically("==", 10))
	})

	It("GetOutputWire()", func() {
		input1 := []byte{1}
		input2 := [][]byte{input1}
		input := [][][]byte{input2}
		garcir := &GarbleCircuit{
			outputWire: input,
		}
		got := garcir.GetOutputWire()
		Expect(got).ShouldNot(BeNil())
	})

	Context("Garbled()", func() {
		It("kBit is a wrong type", func() {
			cir, err := LoadBristol("bristolFashion/ModAdd512.txt")
			Expect(err).Should(BeNil())
			_, _, err = cir.Garbled(1, []byte{1}, EncryptFunc(0))
			Expect(err).ShouldNot(BeNil())
		})

		It("Nonimplement gate", func() {
			cir, err := LoadBristol("bristolFashion/ModAdd512.txt")
			Expect(err).Should(BeNil())
			cir.gates[0].gate = "WOW"
			_, _, err = cir.Garbled(128, []byte{1}, EncryptFunc(0))
			Expect(err).ShouldNot(BeNil())
		})
	})

	It("decrypt", func() {
		d := []int32{10}
		y := []byte{1}
		Y := [][]byte{y}
		got := decrypt(d, Y)
		expected := []byte{11}
		Expect(expected).Should(Equal(got))
	})

	It("SetShaStateBristolInput: the length is wrong", func() {
		_, err := SetShaStateBristolInput([]uint64{8})
		Expect(err).Should(Equal(ErrInputSize))
	})

	It("DecodeBristolFashionOutput: the length is wrong", func() {
		_, err := DecodeBristolFashionOutput([]byte{8})
		Expect(err).ShouldNot(BeNil())
	})

	It("h: the length of index is wrong", func() {
		_, err := h([]byte{1}, big.NewInt(1))
		Expect(err).ShouldNot(BeNil())
	})

	Context("gbAnd()", func() {
		It("LoadBristol(): Does not exist path", func() {
			Wa := []byte{1}
			indexj := big.NewInt(1)
			indexjpai := new(big.Int).Lsh(big1, 16)
			_, _, _, err := gbAnd(Wa, Wa, Wa, Wa, Wa, indexj, indexjpai)
			Expect(err).ShouldNot(BeNil())
		})

		It("LoadBristol(): Nonimplement gate", func() {
			Wa := []byte{1}
			indexj := new(big.Int).Lsh(big1, 16)
			indexjpai := big.NewInt(1)
			_, _, _, err := gbAnd(Wa, Wa, Wa, Wa, Wa, indexj, indexjpai)
			Expect(err).ShouldNot(BeNil())
		})
	})
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

// Just test use. To test the result of parsing is correct.
func (cir *Circuit) evaluate(input [][]uint8) ([][]uint8, error) {
	wires := make([]uint8, cir.countWires)
	// for i := 0; i < len(wires); i++ {
	//  wires[i] = -1
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
		return nil, ErrNONIMPLEMENT
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

func TestCircuit(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Circuit Test")
}
