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

package paillier

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	// maxGenPrimeInt defines the max retries to generate a prime int
	maxGenPrimeInt = 100
)

var (
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
	//ErrInvalidInput is returned if the input is invalid
	ErrInvalidInput = errors.New("invalid input")

	// Big0 is big int 0
	Big0 = big.NewInt(0)
	// Big1 is big int 1
	Big1 = big.NewInt(1)
)

// RandomInt generates a random number in [0, n)
func RandomInt(n *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, n)
}

// RandomCoprimeInt generates a random relative prime number in [0, n)
func RandomCoprimeInt(n *big.Int) (*big.Int, error) {
	for i := 0; i < maxGenPrimeInt; i++ {
		r, err := RandomInt(n)
		if err != nil {
			return nil, err
		}
		if IsRelativePrime(r, n) {
			return r, nil
		}
	}

	return nil, ErrExceedMaxRetry
}

// Gcd calculates greatest common divisor (GCD) via Euclidean algorithm
func Gcd(a *big.Int, b *big.Int) *big.Int {
	return new(big.Int).GCD(nil, nil, a, b)
}

// IsRelativePrime returns if a and b are relative primes
func IsRelativePrime(a *big.Int, b *big.Int) bool {
	return Gcd(a, b).Cmp(Big1) == 0
}

// Lcm calculates find Least Common Multiple
// https://rosettacode.org/wiki/Least_common_multiple#Go
func Lcm(a, b *big.Int) (*big.Int, error) {
	t := Gcd(a, b)
	// avoid panic in Div function
	if t.Cmp(Big0) <= 0 {
		return nil, ErrInvalidInput
	}

	t = t.Div(a, t)
	t = t.Mul(t, b)
	return t, nil
}
