// Copyright © 2019 AMIS Technologies
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

package clhomoencrypt

import (
	"math/big"
	"testing"
)

var BIG_FIELD_ORDER = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
var bigPrime, _ = new(big.Int).SetString(BIG_FIELD_ORDER, 10)
var SAFE_PARAMETER = 1348

// Generate public key and private key associated with discriminant bigPrime * q, where
// bigPrime is the message space and q is a probabilistic "prime" with the bitlength is SAFEPARAMETER.
var publicKey, privateKey, _ = PubKeygen(bigPrime, SAFE_PARAMETER)

func TestDecrypt1(t *testing.T) {
	// origin message
	message := big.NewInt(0)

	// Encrypt the origin message by the public key
	cipherMessege := Encrypt(publicKey, message)

	// decrypt the cipherMessege
	ret := Decrypt(cipherMessege, privateKey)

	if ret.Cmp(message) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", message)
	}
}

func TestDecrypt2(t *testing.T) {
	message := big.NewInt(987)
	cipherMessege := Encrypt(publicKey, message)

	ret := Decrypt(cipherMessege, privateKey)
	if ret.Cmp(message) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", message)
	}
}

func TestDecrypt3(t *testing.T) {
	message := big.NewInt(int64(22971))
	cipherMessege := Encrypt(publicKey, message)
	ret := Decrypt(cipherMessege, privateKey)

	if ret.Cmp(message) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", message)
	}
}

func TestDecrypt4(t *testing.T) {
	message := new(big.Int).Set(bigPrime)
	cipherMessege := Encrypt(publicKey, message)
	ret := Decrypt(cipherMessege, privateKey)

	if ret.Cmp(message.Mod(message, bigPrime)) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", message)
	}
}

func TestDecrypt5(t *testing.T) {
	newbigInt := new(big.Int).Set(bigPrime)
	newbigInt.Add(newbigInt, big.NewInt(2000))
	message := new(big.Int).Set(newbigInt)
	cipherMessege := Encrypt(publicKey, message)
	ret := Decrypt(cipherMessege, privateKey)

	if ret.Cmp(message.Mod(newbigInt, bigPrime)) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", message)
	}
}

func TestDecrypt6(t *testing.T) {
	newbigInt := new(big.Int).Set(bigPrime)
	newbigInt.Sub(newbigInt, bigOne)
	message := new(big.Int).Set(newbigInt)
	cipherMessege := Encrypt(publicKey, message)
	ret := Decrypt(cipherMessege, privateKey)

	if ret.Cmp(message.Mod(newbigInt, bigPrime)) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", message)
	}
}

func TestAdd1(t *testing.T) {
	// Two messages
	message1 := big.NewInt(987)
	message2 := big.NewInt(233)
	expected := new(big.Int).Add(message1, message2)

	// Do encryption
	cipherMessege1 := Encrypt(publicKey, message1)
	cipherMessege2 := Encrypt(publicKey, message2)

	// Perform add to get Encrypt( message1 + message2 )
	sum := EvalAdd(cipherMessege1, cipherMessege2, publicKey)

	// Check sum of decryption is message1 + message2.
	ret := Decrypt(sum, privateKey)

	if ret.Cmp(expected) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", expected)
	}
}

func TestAdd2(t *testing.T) {
	message1 := new(big.Int).Sub(bigPrime, bigOne)
	message2 := big.NewInt(233)
	expected := new(big.Int).Add(message1, message2)
	expected.Mod(expected, bigPrime)

	cipherMessege1 := Encrypt(publicKey, message1)
	cipherMessege2 := Encrypt(publicKey, message2)

	sum := EvalAdd(cipherMessege1, cipherMessege2, publicKey)
	ret := Decrypt(sum, privateKey)

	if ret.Cmp(expected) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", expected)
	}
}

func TestScalar1(t *testing.T) {
	// One message, one scalar
	message := big.NewInt(1)
	scalar := big.NewInt(2)
	expected := new(big.Int).Mul(message, scalar)

	// Encrypt message
	cipherMessege := Encrypt(publicKey, message)

	// Perform EvalMulConst to get Encrypt( message ^ scalar )
	scalarResult := EvalMulConst(cipherMessege, scalar, publicKey)

	ret := Decrypt(scalarResult, privateKey)

	if ret.Cmp(expected) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", expected)
	}
}

func TestScalar2(t *testing.T) {
	message := big.NewInt(9987)
	scalar := big.NewInt(55667788)
	expected := new(big.Int).Mul(message, scalar)

	cipherMessege := Encrypt(publicKey, message)
	scalarResult := EvalMulConst(cipherMessege, scalar, publicKey)

	ret := Decrypt(scalarResult, privateKey)

	if ret.Cmp(expected) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", expected)
	}
}

func TestScalar3(t *testing.T) {
	message := new(big.Int).Set(bigPrime)
	scalar := big.NewInt(55667788)
	expected := new(big.Int).Mul(message, scalar)
	expected.Mod(expected, bigPrime)
	
	cipherMessege := Encrypt(publicKey, message)
	scalarResult := EvalMulConst(cipherMessege, scalar, publicKey)

	ret := Decrypt(scalarResult, privateKey)

	if ret.Cmp(expected) != 0 {
		t.Error("Unexpected Result", "got", ret, "expected", expected)
	}
}

// Benchmark of basic operations: Encrypt, Decrypt, Add, EvalMulConst
func BenchmarkEncryption(b *testing.B) {
	message := big.NewInt(987)
	for i := 0; i < b.N; i++ {
		Encrypt(publicKey, message)
	}
}

func BenchmarkAdd(b *testing.B) {
	message1 := new(big.Int).Sub(bigPrime, bigOne)
	message2 := big.NewInt(233)
	expected := new(big.Int).Add(message1, message2)
	expected.Mod(expected, bigPrime)

	cipherMessege1 := Encrypt(publicKey, message1)
	cipherMessege2 := Encrypt(publicKey, message2)
	for i := 0; i < b.N; i++ {
		EvalAdd(cipherMessege1, cipherMessege2, publicKey)
	}
}

func BenchmarkDecryption(b *testing.B) {
	message := big.NewInt(987)
	cipherMessege := Encrypt(publicKey, message)
	for i := 0; i < b.N; i++ {
		Decrypt(cipherMessege, privateKey)
	}
}

func BenchmarkEvalMulConst(b *testing.B) {
	message := big.NewInt(1)
	scalar := big.NewInt(2)

	cipherMessege := Encrypt(publicKey, message)
	for i := 0; i < b.N; i++ {
		EvalMulConst(cipherMessege, scalar, publicKey)
	}
}
