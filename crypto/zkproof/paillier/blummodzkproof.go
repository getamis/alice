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
	"math/big"

	"github.com/getamis/alice/crypto/utils"
)

const (
	// maxRetry defines the max retries
	maxRetry = 100
	// SAFESECURITYLEVEL define the minimal security level
	SAFESECURITYLEVEL = 2047
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

	w, err := utils.RandomCoprimeInt(n)
	if err != nil {
		return nil, err
	}
	for j := 0; j < maxRetry; j++ {
		if big.Jacobi(w, n) == -1 {
			break
		}
		w, err = utils.RandomCoprimeInt(n)
		if err != nil {
			return nil, err
		}
	}
	nInverEuler := new(big.Int).ModInverse(n, eulerValue)
	deterministicSalt := []byte("Paillier-Blum-Modulus-ZK-Deterministic-Salt")
	for i := 0; i < numberzkProof; i++ {
		yi, err := computeYByDeterministicFiatShamir(deterministicSalt, w, n, ssidInfo, i)
		if err != nil {
			return nil, err
		}

		zi := new(big.Int).Exp(yi, nInverEuler, n)
		ai, bi, xi := get4thRootWithabValue(yi, w, p, q, n)

		x[i] = xi.Bytes()
		a[i] = ai.Bytes()
		b[i] = bi.Bytes()
		z[i] = zi.Bytes()
	}

	return &PaillierBlumMessage{
		A: a,
		B: b,
		W: w.Bytes(),
		X: x,
		Z: z,
	}, nil
}

func (msg *PaillierBlumMessage) Verify(ssidInfo []byte, n *big.Int) error {
	a := msg.A
	b := msg.B
	w := new(big.Int).SetBytes(msg.W)
	x := msg.X
	z := msg.Z

	if len(a) < MINIMALCHALLENGE {
		return ErrInvalidInput 
	}

	if len(a) != len(b) || len(a) != len(x) || len(a) != len(z) {
		return ErrInvalidInput
	}

	if n.BitLen() < SAFESECURITYLEVEL || n.Cmp(big0) < 0 {
		return ErrInvalidInput
	}

	if n.Bit(0) == 0 {
		return ErrInvalidInput
	}

	if n.ProbablyPrime(1) {
		return ErrInvalidInput
	}

	gcd := new(big.Int).GCD(nil, nil, w, n)
	if gcd.Cmp(big1) != 0 {
		return ErrInvalidInput
	}

	if big.Jacobi(w, n) != -1 {
		return ErrInvalidInput
	}

	globalSalt := []byte("Paillier-Blum-Modulus-ZK-Deterministic-Salt")
	for i := 0; i < len(a); i++ {
		yi, err := computeYByDeterministicFiatShamir(globalSalt, w, n, ssidInfo, i)
		if err != nil {
			return err
		}

		zi := new(big.Int).SetBytes(z[i])
		err = utils.InRange(zi, big2, n)
		if err != nil {
			return err
		}

		if new(big.Int).Exp(zi, n, n).Cmp(yi) != 0 {
			return ErrVerifyFailure
		}

		ai := new(big.Int).SetBytes(a[i])
		err = utils.InRange(ai, big0, big2)
		if err != nil {
			return err
		}

		bi := new(big.Int).SetBytes(b[i])
		err = utils.InRange(bi, big0, big2)
		if err != nil {
			return err
		}

		// Compute: (-1)^a * w^b * y mod N
		rightPary := new(big.Int).Set(yi)
		if ai.Cmp(big1) == 0 {
			rightPary.Neg(rightPary)
		}
		if bi.Cmp(big1) == 0 {
			rightPary.Mul(rightPary, w)
		}
		rightPary.Mod(rightPary, n)

		// Compute: x^4 mod N
		if new(big.Int).Exp(new(big.Int).SetBytes(x[i]), big4, n).Cmp(rightPary) != 0 {
			return ErrVerifyFailure
		}
	}
	return nil
}

func computeYByDeterministicFiatShamir(salt []byte, w *big.Int, n *big.Int, ssidInfo []byte, index int) (*big.Int, error) {
	indexBytes := big.NewInt(int64(index)).Bytes()

	for counter := 0; counter < maxRetry; counter++ {
		counterBytes := big.NewInt(int64(counter)).Bytes()
		yi, err := utils.HashProtosWithSaltToScalar(
			salt,
			n,
			utils.GetAnyMsg(ssidInfo, n.Bytes(), w.Bytes(), indexBytes, counterBytes)...,
		)
		if err != nil {
			return nil, err
		}
		if yi.Cmp(big0) == 0 || utils.Gcd(yi, n).Cmp(big1) != 0 {
			continue
		}

		return yi, nil
	}
	return nil, ErrExceedMaxRetry
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
