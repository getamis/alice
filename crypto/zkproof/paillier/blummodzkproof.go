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

package paillier

import (
	"errors"
	"math"
	"math/big"
	"math/rand"

	"github.com/getamis/alice/crypto/utils"
)

const (
	// maxRetry defines the max retries
	maxRetry = 100
)

var (
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
	//ErrInvalidInput is returned if the input is invalid
	ErrInvalidInput = errors.New("invalid input")

	// 2^64 - 1
	max64Bit = new(big.Int).SetUint64(18446744073709551615)
	bit32    = new(big.Int).SetUint64(4294967296)

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big4 = big.NewInt(4)
)

func NewPaillierBlumMessage(ssidInfo []byte, p *big.Int, q *big.Int, n *big.Int, numberzkProof int) (*PaillierBlumMessage, error) {
	eulerValue, err := utils.EulerFunction([]*big.Int{p, q})
	if err != nil {
		return nil, err
	}

	if numberzkProof < MINIMALCHALLENGE {
		return nil, ErrTooFewChallenge
	}
	x := make([][]byte, numberzkProof)
	a := make([][]byte, numberzkProof)
	b := make([][]byte, numberzkProof)
	z := make([][]byte, numberzkProof)
	w := make([][]byte, numberzkProof)
	salt := make([][]byte, numberzkProof)

	for i := 0; i < numberzkProof; i++ {
		// Find w in Z_N such that Jacobi(w, N) = -1.
		wi, err := utils.RandomCoprimeInt(n)
		for j := 0; j < maxRetry; j++ {
			if err != nil {
				return nil, err
			}
			if big.Jacobi(wi, n) == -1 {
				break
			}
			wi, err = utils.RandomCoprimeInt(n)
		}

		salti, err := utils.GenRandomBytes(128)
		if err != nil {
			return nil, err
		}
		// Challenges {yi in Z_N}_{i=1,...,m}.
		yi, salti, err := computeyByRejectSampling(wi, n, salti, ssidInfo)
		if err != nil {
			return nil, err
		}
		// Compute xi = yi^{1/4} mod N with yi=(-1)^ai*w^bi*yi mod N, where ai, bi in {0,1} such that xi is well-defined.
		ai, bi, xi := get4thRootWithabValue(yi, wi, p, q, n)
		zi := new(big.Int).Exp(yi, new(big.Int).ModInverse(n, eulerValue), n)
		x[i] = xi.Bytes()
		a[i] = ai.Bytes()
		b[i] = bi.Bytes()
		z[i] = zi.Bytes()
		w[i] = wi.Bytes()
		salt[i] = salti
	}
	return &PaillierBlumMessage{
		A:    a,
		B:    b,
		W:    w,
		X:    x,
		Z:    z,
		Salt: salt,
	}, nil
}

func (msg *PaillierBlumMessage) Verify(ssidInfo []byte, n *big.Int) error {
	if n.ProbablyPrime(1) || new(big.Int).And(n, big1).Cmp(big0) == 0 {
		return ErrVerifyFailure
	}
	a := msg.A
	b := msg.B
	w := msg.W
	salt := msg.Salt
	x := msg.X
	z := msg.Z

	for i := 0; i < len(a); i++ {
		wi := new(big.Int).SetBytes(w[i])
		yi, _, err := computeyByRejectSampling(wi, n, salt[i], ssidInfo)
		if err != nil {
			return err
		}

		// check zi^n = yi mod n
		if new(big.Int).Exp(new(big.Int).SetBytes(z[i]), n, n).Cmp(yi) != 0 {
			return ErrVerifyFailure
		}
		// xi^4 = (-1)^a*w^b*yi mod n
		rightPary := new(big.Int).Set(yi)
		if new(big.Int).SetBytes(a[i]).Cmp(big1) == 0 {
			rightPary.Neg(rightPary)
		}
		if new(big.Int).SetBytes(b[i]).Cmp(big1) == 0 {
			rightPary.Mul(rightPary, wi)
		}
		rightPary.Mod(rightPary, n)

		if new(big.Int).Exp(new(big.Int).SetBytes(x[i]), big4, n).Cmp(rightPary) != 0 {
			return ErrVerifyFailure
		}
	}
	return nil
}

func computeyByRejectSampling(w *big.Int, n *big.Int, salt []byte, ssidInfo []byte) (*big.Int, []byte, error) {
	nByteLength := uint64(math.Ceil(float64(n.BitLen()) / 8))
	var yi *big.Int
	for j := 0; j < maxRetry; j++ {
		yiSeed, err := utils.HashProtosToInt(salt, utils.GetAnyMsg(ssidInfo, n.Bytes(), w.Bytes())...)
		if err != nil {
			return nil, nil, err
		}
		// Assume that the length of yi is 32 byte
		yi, err = generateIndicateBitLengthInteger(yiSeed, nByteLength)
		if err != nil {
			return nil, nil, err
		}
		if yi.Cmp(n) > -1 || utils.Gcd(yi, n).Cmp(big1) != 0 {
			salt, err = utils.GenRandomBytes(128)
			if err != nil {
				return nil, nil, err
			}
			continue
		}
		return yi, salt, nil
	}
	return nil, nil, ErrExceedMaxRetry
}

func generateIndicateBitLengthInteger(input *big.Int, desiredByteLength uint64) (*big.Int, error) {
	if input.BitLen() > 256 {
		return nil, ErrInvalidInput
	}
	// Assume that the length of yi is 32 byte
	seed := new(big.Int).And(input, max64Bit)
	seed.Xor(seed, new(big.Int).Lsh(input, 64))
	seed.Xor(seed, new(big.Int).Lsh(input, 128))
	seed.Xor(seed, new(big.Int).Lsh(input, 196))
	seed.Sub(seed, bit32)
	rand.Seed(seed.Int64())

	result := make([]byte, desiredByteLength)
	for i := 0; i < len(result); i++ {
		result[i] = byte(rand.Intn(256))
	}
	return new(big.Int).SetBytes(result), nil
}

// In our context, p = 3 mod 4 and q = 3 mod 4.
func get4thRootWithabValue(y *big.Int, w *big.Int, p *big.Int, q *big.Int, n *big.Int) (*big.Int, *big.Int, *big.Int) {
	yModp := new(big.Int).Mod(y, p)
	wModp := new(big.Int).Mod(w, p)
	yModq := new(big.Int).Mod(y, q)
	wModq := new(big.Int).Mod(w, q)

	var a, b *big.Int
	if big.Jacobi(yModp, p) == -1 {
		if big.Jacobi(yModq, q) == -1 {
			a = big.NewInt(1)
			b = big.NewInt(0)

		} else {
			if big.Jacobi(wModp, p) == -1 {
				a = big.NewInt(0)
				b = big.NewInt(1)
			} else {
				a = big.NewInt(1)
				b = big.NewInt(1)
			}
		}
	} else {
		if big.Jacobi(yModq, q) == -1 {
			if big.Jacobi(wModp, p) == -1 {
				a = big.NewInt(1)
				b = big.NewInt(1)

			} else {
				a = big.NewInt(0)
				b = big.NewInt(1)

			}
		} else {
			a = big.NewInt(0)
			b = big.NewInt(0)
		}
	}
	resultModp := new(big.Int).Set(yModp)
	resultModq := new(big.Int).Set(yModq)
	if a.Cmp(big1) == 0 {
		resultModp = resultModp.Neg(resultModp)
		resultModq = resultModq.Neg(resultModq)
	}
	if b.Cmp(big1) == 0 {
		resultModp.Mul(resultModp, wModp)
		resultModq.Mul(resultModq, wModq)
	}

	resultModp.ModSqrt(resultModp, p)
	resultModp.ModSqrt(resultModp, p)
	resultModq.ModSqrt(resultModq, q)
	resultModq.ModSqrt(resultModq, q)

	u := big.NewInt(1)
	v := big.NewInt(1)
	new(big.Int).GCD(u, v, p, q)
	result := new(big.Int).Mul(new(big.Int).Mul(p, u), resultModq)
	result.Add(result, new(big.Int).Mul(new(big.Int).Mul(q, v), resultModp))
	result.Mod(result, n)
	return a, b, result
}
