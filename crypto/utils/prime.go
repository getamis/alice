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
	"io"
	"math/big"
)

var (
	// 16294579238595022365 = 3 * primeProducts[0]
	prime3Product = new(big.Int).SetUint64(16294579238595022365)
	// without prime 3
	primes = [][]uint64{
		{
			5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
		},
		{
			59, 61, 67, 71, 73, 79, 83, 89, 97,
		},
		{
			101, 103, 107, 109, 113, 127, 131, 137, 139,
		},
		{
			149, 151, 157, 163, 167, 173, 179, 181,
		},
		{
			191, 193, 197, 199, 211, 223, 227, 229,
		},
		{
			233, 239, 241, 251, 257, 263, 269,
		},
		{
			271, 277, 281, 283, 293, 307, 311,
		},
		{
			317, 331, 337, 347, 349, 353, 359,
		},
		{
			367, 373, 379, 383, 389, 397, 401,
		},
		{
			409, 419, 421, 431, 433, 439, 443,
		},
		{
			449, 457, 461, 463, 467, 479, 487,
		},
		{
			491, 499, 503, 509, 521, 523, 541,
		},
		{
			557, 563, 569, 571, 577, 587,
		},
		{
			593, 599, 601, 607, 613, 617,
		},
		{
			619, 631, 641, 643, 647, 653,
		},
		{
			659, 661, 673, 677, 683, 691,
		},
		{
			701, 709, 719, 727, 733, 739,
		},
		{
			743, 751, 757, 761, 769, 773,
		},
		{
			787, 797, 809, 811, 821, 823,
		},
		{
			827, 829, 839, 853, 857, 859,
		},
		{
			863, 877, 881, 883, 887, 907,
		},
		{
			911, 919, 929, 937, 941, 947,
		},
		{
			953, 967, 971, 977, 983, 991,
		},
	}

	primeProducts = []*big.Int{
		new(big.Int).SetUint64(5431526412865007455),
		new(big.Int).SetUint64(6437928885641249269),
		new(big.Int).SetUint64(4343678784233766587),
		new(big.Int).SetUint64(538945254996352681),
		new(big.Int).SetUint64(3534749459194562711),
		new(big.Int).SetUint64(61247129307885343),
		new(big.Int).SetUint64(166996819598798201),
		new(big.Int).SetUint64(542676746453092519),
		new(big.Int).SetUint64(1230544604996048471),
		new(big.Int).SetUint64(2618501576975440661),
		new(big.Int).SetUint64(4771180125133726009),
		new(big.Int).SetUint64(9247077179230889629),
		new(big.Int).SetUint64(34508483876655991),
		new(big.Int).SetUint64(49010633640532829),
		new(big.Int).SetUint64(68015277240951437),
		new(big.Int).SetUint64(93667592535644987),
		new(big.Int).SetUint64(140726526226538479),
		new(big.Int).SetUint64(191079950785756457),
		new(big.Int).SetUint64(278064420037666463),
		new(big.Int).SetUint64(361197734649700343),
		new(big.Int).SetUint64(473672212426732757),
		new(big.Int).SetUint64(649424689916978839),
		new(big.Int).SetUint64(851648411420003101),
	}
)

// p, q are primes and p = 2*q+1
type SafePrime struct {
	P *big.Int
	Q *big.Int
}

// The algorithm appears in the paper Safe Prime Generation with a Combined Sieve
// https://eprint.iacr.org/2003/186.pdf
// safe prime: p = 2q+1, where p and q are both primes.
func GenerateRandomSafePrime(rand io.Reader, pbits int) (*SafePrime, error) {
	if pbits < 3 {
		return nil, ErrSmallSafePrime
	}
	upperbound := uint64(1024)
	bits := pbits - 1
	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}
	bytes := make([]byte, (bits+7)/8)
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
		q := new(big.Int).SetBytes(bytes)

		// Calculate the value mod the product of primes[0]. If it's
		// a multiple of any of these primes we add two until it isn't.
		// The probability of overflowing is minimal and can be ignored
		// because we still perform Miller-Rabin tests on the result.
		bigMod := new(big.Int).Mod(q, prime3Product)
		mod3 := FastMod3(bigMod)
		if mod3 == 1 {
			q.Add(q, big4)
		} else if mod3 == 0 {
			q.Add(q, big2)
		}

	NextDelta:
		for delta := uint64(0); delta < upperbound; delta += 6 {
			candidateQ := new(big.Int).Add(q, new(big.Int).SetUint64(delta))
			for i := 0; i < len(primeProducts); i++ {
				if !checkPrimes(candidateQ, primeProducts[i], primes[i]) {
					continue NextDelta
				}
			}
			q2 := new(big.Int).Lsh(candidateQ, 1)
			candidateP := new(big.Int).Add(q2, big1)
			if !checkPrimeByPocklingtonCriterion(q2, candidateP) || candidateP.BitLen() != pbits {
				continue NextDelta
			}
			// So far, there is no prime which can pass Miller-Rabin test and Lucas test simultaneously.
			if !candidateQ.ProbablyPrime(1) {
				continue NextDelta
			}
			return &SafePrime{
				P: candidateP,
				Q: candidateQ,
			}, nil
		}
	}
}

func checkPrimes(m *big.Int, product *big.Int, primes []uint64) bool {
	mm := new(big.Int).Mod(m, product).Uint64()
	for _, prime := range primes {
		residue := mm % prime
		if residue == 0 {
			return false
		}
		r := prime >> 1
		if residue == r {
			return false
		}
	}
	return true
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
func checkPrimeByPocklingtonCriterion(pMinus1, p *big.Int) bool {
	apower := new(big.Int).Exp(big2, pMinus1, p)
	return apower.Cmp(big1) == 0
}
