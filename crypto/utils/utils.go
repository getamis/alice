// Copyright © 2020 AMIS Technologies
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

package utils

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"golang.org/x/crypto/blake2b"
)

const (
	// SaltSize is based on blake2b256
	SaltSize = 32
	// maxGenHashValue defines the max retries to generate hash value by reject sampling
	maxGenNHashValue = 100
	// minPermittedThreshold
	minPermittedThreshold = 2
)

var (
	// ErrLessOrEqualBig2 is returned if the field order is less than or equal to 2
	ErrLessOrEqualBig2 = errors.New("less 2")
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
	//ErrInvalidInput is returned if the input is invalid
	ErrInvalidInput = errors.New("invalid input")
	//ErrLargeRank is returned if the rank is too large
	ErrLargeRank = errors.New("large rank")
	//ErrLargeThreshold is returned if the threshold is too large
	ErrLargeThreshold = errors.New("large threshold")
	// ErrNotInRange is returned if the value is not in the given range.
	ErrNotInRange = errors.New("not in range")
	// ErrLargerFloor is returned if the floor is larger than ceil.
	ErrLargerFloor = errors.New("larger floor")
	// ErrEmptySlice is returned if the length of slice is zero.
	ErrEmptySlice = errors.New("empty slice")
	// ErrSmallThreshold is returned if the threshold < 2.
	ErrSmallThreshold = errors.New("threshold < 2")
	// ErrSmallSafePrime is returned if the safePrime < 2^10.
	ErrSmallSafePrime = errors.New("safe-prime size must be at least 10-bit")

	// maxGenPrimeInt defines the max retries to generate a prime int
	maxGenPrimeInt = 100

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
)

// EnsureFieldOrder ensures the field order should be more than 2.
func EnsureFieldOrder(fieldOrder *big.Int) error {
	if fieldOrder.Cmp(big2) <= 0 {
		return ErrLessOrEqualBig2
	}
	return nil
}

// EnsureRank ensures the rank+1 should be smaller than threshold.
func EnsureRank(rank uint32, threshold uint32) error {
	if rank+1 >= threshold {
		return ErrLargeRank
	}
	return nil
}

// EnsureThreshold ensures the threshold should be smaller than or equal to n.
func EnsureThreshold(threshold uint32, n uint32) error {
	if threshold > n {
		return ErrLargeThreshold
	}
	if threshold < minPermittedThreshold {
		return ErrSmallThreshold
	}

	return nil
}

// RandomInt generates a random number in [0, n).
func RandomInt(n *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, n)
}

// RandomPositiveInt generates a random number in [1, n).
func RandomPositiveInt(n *big.Int) (*big.Int, error) {
	x, err := RandomInt(new(big.Int).Sub(n, big1))
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(x, big1), nil
}

// RandomPrime generates a random prime number with bits size
func RandomPrime(bits int) (*big.Int, error) {
	return rand.Prime(rand.Reader, bits)
}

// RandomCoprimeInt generates a random relative prime number in [2, n)
func RandomCoprimeInt(n *big.Int) (*big.Int, error) {
	if n.Cmp(big2) <= 0 {
		return nil, ErrLessOrEqualBig2
	}
	for i := 0; i < maxGenPrimeInt; i++ {
		r, err := RandomInt(n)
		if err != nil {
			return nil, err
		}
		// Try again if r == 0 or 1
		if r.Cmp(big1) <= 0 {
			continue
		}
		if IsRelativePrime(r, n) {
			return r, nil
		}
	}

	return nil, ErrExceedMaxRetry
}

// IsRelativePrime returns if a and b are relative primes
func IsRelativePrime(a *big.Int, b *big.Int) bool {
	return Gcd(a, b).Cmp(big1) == 0
}

// Gcd calculates greatest common divisor (GCD) via Euclidean algorithm
func Gcd(a *big.Int, b *big.Int) *big.Int {
	return new(big.Int).GCD(nil, nil, a, b)
}

// Lcm calculates find Least Common Multiple
// https://rosettacode.org/wiki/Least_common_multiple#Go
func Lcm(a, b *big.Int) (*big.Int, error) {
	if a.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}
	if b.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}
	t := Gcd(a, b)
	// avoid panic in Div function
	if t.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}

	t = t.Div(a, t)
	t = t.Mul(t, b)
	return t, nil
}

// EulerFunction :(Special case) Assume that N is square-free and primeFactor consists of prime integers. Formula: N = prod_i P_i, the output is prod_i (P_i -1).
// TODO: general case.
func EulerFunction(primeFactor []*big.Int) (*big.Int, error) {
	if len(primeFactor) == 0 {
		return nil, ErrInvalidInput
	}
	result := big.NewInt(1)
	for i := 0; i < len(primeFactor); i++ {
		temp := primeFactor[i]
		if temp.Cmp(big1) <= 0 {
			return nil, ErrInvalidInput
		}
		result = new(big.Int).Mul(result, new(big.Int).Sub(temp, big1))
	}
	return result, nil
}

// InRange checks if the checkValue is in [floor, ceil).
func InRange(checkValue *big.Int, floor *big.Int, ceil *big.Int) error {
	if ceil.Cmp(floor) < 1 {
		return ErrLargerFloor
	}
	if checkValue.Cmp(floor) < 0 {
		return ErrNotInRange
	}
	if checkValue.Cmp(ceil) > -1 {
		return ErrNotInRange
	}
	return nil
}

// GenRandomBytes generates a random byte array with indicating the legnth.
func GenRandomBytes(size int) ([]byte, error) {
	if size < 1 {
		return nil, ErrEmptySlice
	}
	randomByte := make([]byte, size)
	_, err := rand.Read(randomByte)
	if err != nil {
		return nil, err
	}
	return randomByte, nil
}

// Waring: The follwing function only work in S256 and P256, because the output of blake2b is 32 byte.
// HashProtosToInt hashes a slice of message to an integer.
func HashProtosToInt(salt []byte, msgs ...proto.Message) (*big.Int, error) {
	bs, err := HashProtos(salt, msgs...)
	if err != nil {
		return nil, err
	}
	c := new(big.Int).SetBytes(bs)
	return c, nil
}

func HashProtosRejectSampling(fieldOrder *big.Int, msgs ...proto.Message) (*big.Int, []byte, error) {
	for i := 0; i < maxGenNHashValue; i++ {
		salt, err := GenRandomBytes(SaltSize)
		if err != nil {
			return nil, nil, err
		}
		c, err := HashProtosToInt(salt, msgs...)
		if err != nil {
			return nil, nil, err
		}

		err = InRange(c, big0, fieldOrder)
		if err == nil {
			return c, salt, nil
		}
	}
	return nil, nil, ErrExceedMaxRetry
}

// HashProtos hashes a slice of message.
func HashProtos(salt []byte, msgs ...proto.Message) ([]byte, error) {
	// hash message
	hMsg := &Hash{
		Msgs: make([]*any.Any, len(msgs)+1),
	}
	for i, m := range msgs {
		anyMsg, err := ptypes.MarshalAny(m)
		if err != nil {
			return nil, err
		}
		hMsg.Msgs[i] = anyMsg
	}
	hMsg.Msgs[len(msgs)] = &any.Any{
		Value: salt,
	}
	inputData, err := proto.Marshal(hMsg)
	if err != nil {
		return nil, err
	}
	bs := blake2b.Sum256(inputData)
	return bs[:], nil
}

// The algorithm appear in the paper Safe Prime Generation with a Combined Sieve
// https://eprint.iacr.org/2003/186.pdf
// safe prime: p = 2q+1, where p and q are both primes.
func SafePrime(rand io.Reader, pbits int) (*big.Int, error) {
	if pbits < 10 {
		return nil, ErrSmallSafePrime
	}
	bits := pbits - 1
	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}
	bytes := make([]byte, (bits+7)/8)
	p := new(big.Int)
	q := new(big.Int)
	bigMod := new(big.Int)
	for {
		_, err := io.ReadFull(rand, bytes)
		if err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<b) - 1)
		// Don't let the value be too small, i.e, set the most significant two bits.
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
				// Prime returns a number, p, of the given size, such that p is prime
				// with high probability.
				// Prime will return error for any error returned by rand.Read or if bits < 2.

			}
		}
		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1
		q.SetBytes(bytes)

		// Calculate the value mod the product of smallPrimes. If it's
		// a multiple of any of these primes we add two until it isn't.
		// The probability of overflowing is minimal and can be ignored
		// because we still perform Miller-Rabin tests on the result.
		bigMod.Mod(q, smallPrimesProduct)
		mod := bigMod.Mod(q, smallPrimesProduct).Uint64()
		mod3 := FastMod3(bigMod)
		if mod3 == 1 {
			q.Add(q, big1)
			mod = mod + 1
		} else if mod3 == 0 {
			q.Add(q, big2)
			mod = mod + 2
		}

	NextDelta:
		for delta := uint64(0); delta < 1<<20; delta += 6 {
			m := mod + delta
			for _, prime := range smallPrimes {
				primeInt64 := uint64(prime)
				residue := m % primeInt64
				if residue == 0 && (bits > 6 || m != primeInt64) {
					continue NextDelta
				}

				r := primeInt64 >> 1
				if residue == r {
					continue NextDelta
				}
			}

			if delta > 0 {
				bigMod.SetUint64(delta)
				q.Add(q, bigMod)
			}

			// p = 2q+1
			p.Lsh(q, 1)
			p.Add(p, big1)
			resediueP := new(big.Int).Mod(q, smallPrimesProduct).Uint64()
			for i := 0; i < len(smallPrimes); i++ {
				nmod := resediueP % uint64(smallPrimes[i])
				r := uint64(smallPrimes[i]) >> 1
				if nmod == r || nmod == 0 {
					continue NextDelta
				}
			}

			for i := 0; i < len(otherSmallPrimesList); i++ {
				if !checkSafePrime(p, q, otherSmallPrimeProductList[i], otherSmallPrimesList[i]) {
					continue NextDelta
				}
			}
			break
		}

		// So far, there is no prime which can pass Miller-Rabin test and Lucas test simultaneously.
		if q.ProbablyPrime(1) && checkPrimeByPocklingtonCriterion(p) && p.BitLen() == pbits {
			return p, nil
		}
	}
}

// This is a algorithm to get number % 3. The velocity of this function is faster than new(bigInt).mod(number, 3).
func FastMod3(number *big.Int) int {
	numberOne, numberTwo := 0, 0
	for i := 0; i < number.BitLen(); i = i + 2 {
		if number.Bit(i) != 0 {
			numberOne++
		}
	}
	for i := 1; i < number.BitLen(); i = i + 2 {
		if number.Bit(i) != 0 {
			numberTwo++
		}
	}
	result := 0
	if numberOne > numberTwo {
		result = numberOne - numberTwo
	} else {
		result = numberTwo - numberOne
		result = result << 1
	}
	return result % 3
}

// Pocklington's criterion can used to prove that p = 2q+1 is prime.
// ref: https://en.wikipedia.org/wiki/Pocklington_primality_test
func checkPrimeByPocklingtonCriterion(p *big.Int) bool {
	apower := new(big.Int).Exp(big2, new(big.Int).Sub(p, big1), p)
	return apower.Cmp(big1) == 0
}

func checkSafePrime(p, q, product *big.Int, primeList []uint64) bool {
	modP := new(big.Int).Mod(p, product).Uint64()
	modQ := new(big.Int).Mod(q, product).Uint64()
	for i := 0; i < len(primeList); i++ {
		r := primeList[i] >> 1
		resediueBigQ := modQ % primeList[i]
		resediueBigP := modP % primeList[i]
		if resediueBigQ == r || resediueBigQ == 0 {
			return false
		}
		if resediueBigP == r || resediueBigP == 0 {
			return false
		}
	}
	return true
}
