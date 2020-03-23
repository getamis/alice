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
)

var (
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")

	big0 = big.NewInt(0)
	big2 = big.NewInt(2)
)

/*
	Note that: we assume that N is square-free(i.e. for any prime p | N, then p^2 does not divide N).
	Let N be a large positive integer. If we do not know the knowledge of the factorization of N, then it is hard to compute phi(N).
	Here phi is the well-known Euler phi function. Using this fact, we can use the following zero knowledge proof of the integer factorization.
	In our case, N is the public key
	Step 1: A prover generates
	- a challenge x, a coprime with the public key (in Z_N^\ast and not 1)
	- its proof, M = N^(-1) mod \phi(N) and the proof is x^M mod N
	- public key
	Step 2: The verifier checks iff x != 1, proof in [0,N) and y^N = x mod N.
*/

func NewIntegerFactorizationProofMessage(primeFactor []*big.Int, publicKey *big.Int) (*IntegerFactorizationProofMessage, error) {
	// Compute challenge
	challenge, err := utils.RandomCoprimeInt(publicKey)
	if err != nil {
		return nil, err
	}

	// Compute proof
	eulerValue, err := utils.EulerFunction(primeFactor)
	if err != nil {
		return nil, err
	}
	challengeInverse := new(big.Int).ModInverse(publicKey, eulerValue)
	v := new(big.Int).Exp(challenge, challengeInverse, publicKey)

	msg := &IntegerFactorizationProofMessage{
		PublicKey: publicKey.Bytes(),
		Challenge: challenge.Bytes(),
		Proof:     v.Bytes(),
	}

	// Ensure it's a valid message
	err = msg.Verify()
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (msg *IntegerFactorizationProofMessage) Verify() error {
	publicKey := new(big.Int).SetBytes(msg.GetPublicKey())
	proof := new(big.Int).SetBytes(msg.GetProof())
	err := utils.InRange(proof, big0, publicKey)
	if err != nil {
		return err
	}
	challenge := new(big.Int).SetBytes(msg.GetChallenge())
	err = utils.InRange(challenge, big2, publicKey)
	if err != nil {
		return err
	}
	expected := new(big.Int).Exp(proof, publicKey, publicKey)
	if expected.Cmp(challenge) != 0 {
		return ErrVerifyFailure
	}
	return nil
}
