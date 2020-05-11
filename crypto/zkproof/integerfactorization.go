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

package zkproof

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/ptypes/any"
	"golang.org/x/crypto/blake2b"
)

const (
	// safePubKeySize is the permitted lowest size of Public Key.
	safePubKeySize = 2048

	// maxRetry defines the max retries to generate proof
	maxRetry = 100
)

var (
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
	//ErrSmallPublicKeySize is returned if the size of public key is small
	ErrSmallPublicKeySize = errors.New("small public key")
	//ErrNotCoprime is returned if two integers are not coprime
	ErrNotCoprime = errors.New("two integers are not coprime")
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)

	// B
	chellengeSize = big.NewInt(1024)
)

/*
	Note that: we assume that N is square-free(i.e. for any prime p | N, then p^2 does not divide N).
	Let N be a large positive integer. If we do not know the knowledge of the factorization of N, then it is hard to compute phi(N).
	Here phi is the well-known Euler phi function. Using this fact, we can use the following zero knowledge proof of the integer factorization.
	The following interactive protocol comes from the paper: "Short Proofs of Knowledge for Factoring".
	In our case, N is the public key
	Step 1: A prover generates
	- The prover randomly chooses an integer r in [1,A-1] and z in Z_N^\ast.
	- The prover computes x = z^r mod N.
	- The prover computes e := H(x, z, N) mod B
	- The prover computes y:= r+(N-phi(N))*e. The resulting proof is the (x, y, z)
	Step 2: The verifier checks x in [1,N-1], y in [0,A-1](Note: this check has small possibility to failure), z in Z_N^ast, and z^(y-N*e) = x mod N.

	Remark: We take A = N-1.
*/

func NewIntegerFactorizationProofMessage(primeFactor []*big.Int, publicKey *big.Int) (*IntegerFactorizationProofMessage, error) {
	if publicKey.BitLen() < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}

	for i := 0; i < maxRetry; i++ {
		// Compute A = N-1
		A := new(big.Int).Sub(publicKey, big1)

		// Choose r in [0,A-1]
		r, err := utils.RandomPositiveInt(A)
		if err != nil {
			return nil, err
		}

		// Get z in Z_N^\ast
		z, err := utils.RandomCoprimeInt(publicKey)
		if err != nil {
			return nil, err
		}
		x := new(big.Int).Exp(z, r, publicKey)

		// Compute e := H(x, z, N)
		blake2bKey, err := utils.GenRandomBytes(blake2b.Size256)
		if err != nil {
			return nil, err
		}
		e, err := utils.HashProtos(blake2bKey, chellengeSize, &any.Any{
			Value: x.Bytes(),
		}, &any.Any{
			Value: z.Bytes(),
		}, &any.Any{
			Value: publicKey.Bytes(),
		})
		if err != nil {
			return nil, err
		}

		// Compute y:= r+(N-phi(N))*e mod N
		eulerValue, err := utils.EulerFunction(primeFactor)
		if err != nil {
			return nil, err
		}
		y := new(big.Int).Sub(publicKey, eulerValue)
		y = y.Mul(y, e)
		y = y.Add(r, y)

		msg := &IntegerFactorizationProofMessage{
			Blake2BKey: blake2bKey,
			PublicKey:  publicKey.Bytes(),
			X:          x.Bytes(),
			Y:          y.Bytes(),
			Z:          z.Bytes(),
		}

		// Ensure it's a valid message
		err = msg.Verify()
		if err != nil {
			return nil, err
		} else {
			return msg, nil
		}
	}
	return nil, ErrExceedMaxRetry
}

func (msg *IntegerFactorizationProofMessage) Verify() error {
	publicKey := new(big.Int).SetBytes(msg.GetPublicKey())

	// Check x in [1,N-1]
	x := new(big.Int).SetBytes(msg.GetX())
	err := utils.InRange(x, big1, publicKey)
	if err != nil {
		return err
	}

	// Check y in [0,A-1]
	A := new(big.Int).Sub(publicKey, big1)
	y := new(big.Int).SetBytes(msg.GetY())
	err = utils.InRange(y, big0, A)
	if err != nil {
		return err
	}

	// z in Z_N^ast
	z := new(big.Int).SetBytes(msg.GetZ())
	if !utils.IsRelativePrime(z, publicKey) {
		return ErrNotCoprime
	}

	// Compute e := H(x, z, N)
	blake2bKey := msg.GetBlake2BKey()
	e, err := utils.HashProtos(blake2bKey, chellengeSize, &any.Any{
		Value: x.Bytes(),
	}, &any.Any{
		Value: z.Bytes(),
	}, &any.Any{
		Value: publicKey.Bytes(),
	})
	if err != nil {
		return err
	}

	// Compute z^(y-N*e) = x mod N
	exponent := new(big.Int).Mul(publicKey, e)
	exponent = exponent.Sub(y, exponent)
	expected := new(big.Int).Exp(z, exponent, publicKey)

	if expected.Cmp(x) != 0 {
		return ErrVerifyFailure
	}
	return nil
}
