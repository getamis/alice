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

package childnewversion

import (
	"crypto/sha512"
	"errors"
	"hash"
	"math"
	"math/bits"
	"strconv"
	"sync"

	"github.com/getamis/alice/crypto/utils"
)

/*
	We implement a version of "garbled circuit" according to paper: "Better Concrete Security for Half-Gates Garbling"
	and "Two Halves Make a Whole Reducing data Transfer in Garbled Circuits using Half Gates".
	We support the parse of Bristol fashion ref: https://homes.esat.kuleuven.be/~nsmart/MPC/
*/
const (
	MAXUINT32       = 2147483647
	SHA512BlOCKSIZE = 1024
	MAXUINT64       = 18446744073709551615

	SHA512PADDING = 896

	init0 = 0x6a09e667f3bcc908
	init1 = 0xbb67ae8584caa73b
	init2 = 0x3c6ef372fe94f82b
	init3 = 0xa54ff53a5f1d36f1
	init4 = 0x510e527fade682d1
	init5 = 0x9b05688c2b3e6c1f
	init6 = 0x1f83d9abfb41bd6b
	init7 = 0x5be0cd19137e2179
)

var (
	ConstantSHA512 = []uint64{
		0x428a2f98d728ae22,
		0x7137449123ef65cd,
		0xb5c0fbcfec4d3b2f,
		0xe9b5dba58189dbbc,
		0x3956c25bf348b538,
		0x59f111f1b605d019,
		0x923f82a4af194f9b,
		0xab1c5ed5da6d8118,
		0xd807aa98a3030242,
		0x12835b0145706fbe,
		0x243185be4ee4b28c,
		0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f,
		0x80deb1fe3b1696b1,
		0x9bdc06a725c71235,
		0xc19bf174cf692694,
		0xe49b69c19ef14ad2,
		0xefbe4786384f25e3,
		0x0fc19dc68b8cd5b5,
		0x240ca1cc77ac9c65,
		0x2de92c6f592b0275,
		0x4a7484aa6ea6e483,
		0x5cb0a9dcbd41fbd4,
		0x76f988da831153b5,
		0x983e5152ee66dfab,
		0xa831c66d2db43210,
		0xb00327c898fb213f,
		0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2,
		0xd5a79147930aa725,
		0x06ca6351e003826f,
		0x142929670a0e6e70,
		0x27b70a8546d22ffc,
		0x2e1b21385c26c926,
		0x4d2c6dfc5ac42aed,
		0x53380d139d95b3df,
		0x650a73548baf63de,
		0x766a0abb3c77b2a8,
		0x81c2c92e47edaee6,
		0x92722c851482353b,
		0xa2bfe8a14cf10364,
		0xa81a664bbc423001,
		0xc24b8b70d0f89791,
		0xc76c51a30654be30,
		0xd192e819d6ef5218,
		0xd69906245565a910,
		0xf40e35855771202a,
		0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8,
		0x1e376c085141ab53,
		0x2748774cdf8eeb99,
		0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63,
		0x4ed8aa4ae3418acb,
		0x5b9cca4f7763e373,
		0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc,
		0x78a5636f43172f60,
		0x84c87814a1f0ab72,
		0x8cc702081a6439ec,
		0x90befffa23631e28,
		0xa4506cebde82bde9,
		0xbef9a3f7b2c67915,
		0xc67178f2e372532b,
		0xca273eceea26619c,
		0xd186b8c721c0c207,
		0xeada7dd6cde0eb1e,
		0xf57d4f7fee6ed178,
		0x06f067aa72176fba,
		0x0a637dc5a2c898a6,
		0x113f9804bef90dae,
		0x1b710b35131c471b,
		0x28db77f523047d84,
		0x32caab7b40c72493,
		0x3c9ebe0a15c9bebc,
		0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6,
		0x597f299cfc657e2a,
		0x5fcb6fab3ad6faec,
		0x6c44198c4a475817,
	}

	// ErrInputSizeLarge is returned if the size of input is too large
	ErrInputSizeLarge = errors.New("large input")
)

type hmacSHA512 struct {
	hash.Hash

	opad []byte
	ipad []byte
	mu   sync.Mutex
}

func NewHmacSha512(key []byte) *hmacSHA512 {
	h := sha512.New()
	blocksize := h.BlockSize()
	hm := &hmacSHA512{
		Hash: h,
		opad: make([]byte, blocksize),
		ipad: make([]byte, blocksize),
	}

	// If key is too big, hash it.
	if len(key) > blocksize {
		h1 := sha512.New()
		h1.Write(key)
		key = h1.Sum(nil)
	}

	copy(hm.ipad, key)
	copy(hm.opad, key)
	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36
	}
	for i := range hm.opad {
		hm.opad[i] ^= 0x5c
	}
	return hm
}

func (h *hmacSHA512) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Hash.Reset()
	h.Hash.Write(h.ipad)
}

func (h *hmacSHA512) Digest(innerHash []byte) []byte {
	h1 := sha512.New()
	h1.Write(h.opad)
	h1.Write(innerHash)
	return h1.Sum(nil)
}

// Only Support len(data) < 896
func (h *hmacSHA512) ComputeFirstBlockHash() ([]uint64, error) {
	return computeFirstBlockHash(h.ipad)
}

func (h *hmacSHA512) ComputeOutputFirstBlockHash() ([]uint64, error) {
	return computeFirstBlockHash(h.opad)
}

func (h *hmacSHA512) GetSecondBlockHash(data []byte) ([]byte, error) {
	return getSecondBlockHash(data, h.ipad)
}

func (h *hmacSHA512) GetOutputSecondBlockHash(data []byte) ([]byte, error) {
	return getSecondBlockHash(data, h.opad)
}

func Sha512GetBlockWithPadding(p []byte) ([]byte, error) {
	// Check input size
	result := utils.BytesToBits(p)
	bitLength := len(result)
	if bitLength > MAXUINT32 {
		return nil, ErrInputSizeLarge
	}
	result = append(result, byte(1))

	stringbinary := strconv.FormatInt(int64(bitLength), 2)
	lengthbit := make([]uint8, len(stringbinary))
	for i := 0; i < len(lengthbit); i++ {
		if stringbinary[i] == '0' {
			lengthbit[i] = 0
		} else {
			lengthbit[i] = 1
		}
	}

	// Padding 0
	upBd := math.Ceil(float64(bitLength+1-SHA512PADDING) / SHA512BlOCKSIZE)
	K := ((uint64(upBd) + 1) * SHA512BlOCKSIZE) - uint64(len(stringbinary)) - uint64(bitLength) - 1
	zeropad := make([]uint8, K)
	result = append(result, zeropad...)
	result = append(result, lengthbit...)
	return result, nil
}

// WARN: p is bit-Slice
func Sha512Compression(p []byte, preState []uint64) []uint64 {
	a := preState[0]
	b := preState[1]
	c := preState[2]
	d := preState[3]
	e := preState[4]
	f := preState[5]
	g := preState[6]
	h := preState[7]
	p, _ = utils.BitsToBytes(p)

	var w [80]uint64
	for i := 0; i < 16; i++ {
		j := i * 8
		w[i] = uint64(p[j])<<56 | uint64(p[j+1])<<48 | uint64(p[j+2])<<40 | uint64(p[j+3])<<32 |
			uint64(p[j+4])<<24 | uint64(p[j+5])<<16 | uint64(p[j+6])<<8 | uint64(p[j+7])
	}
	for i := 16; i < 80; i++ {
		v1 := w[i-2]
		t1 := bits.RotateLeft64(v1, -19) ^ bits.RotateLeft64(v1, -61) ^ (v1 >> 6)
		v2 := w[i-15]
		t2 := bits.RotateLeft64(v2, -1) ^ bits.RotateLeft64(v2, -8) ^ (v2 >> 7)
		w[i] = t1 + w[i-7] + t2 + w[i-16]
	}
	for i := 0; i < 80; i++ {
		t1 := h + (bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^ bits.RotateLeft64(e, -41)) + ((e & f) ^ (^e & g)) + ConstantSHA512[i] + w[i]
		t2 := (bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^ bits.RotateLeft64(a, -39)) + ((a & b) ^ (a & c) ^ (b & c))
		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}

	return []uint64{
		a + preState[0],
		b + preState[1],
		c + preState[2],
		d + preState[3],
		e + preState[4],
		f + preState[5],
		g + preState[6],
		h + preState[7],
	}
}

func computeFirstBlockHash(pad []byte) ([]uint64, error) {
	paddingResult, err := Sha512GetBlockWithPadding(pad)
	if err != nil {
		return nil, err
	}
	return Sha512Compression(paddingResult[0:1024], sha512InitialState()), nil
}

func getSecondBlockHash(data []byte, pad []byte) ([]byte, error) {
	if len(data) >= (SHA512PADDING >> 3) {
		return nil, ErrInputSizeLarge
	}
	message := append(pad, data...)

	paddingResult, err := Sha512GetBlockWithPadding(message)
	if err != nil {
		return nil, err
	}
	return paddingResult[1024:], nil
}

func sha512InitialState() []uint64 {
	return []uint64{
		init0,
		init1,
		init2,
		init3,
		init4,
		init5,
		init6,
		init7,
	}
}
