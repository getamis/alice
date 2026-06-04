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

var (
	//ErrTooFewChallenge is returned if the times of challenge is too few.
	ErrTooFewChallenge = errors.New("the times of challenge are too few")
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
)

func NewRingPederssenParameterMessage(ssidInfo []byte, eulerValue *big.Int, n *big.Int, s *big.Int, t *big.Int, lambda *big.Int, nubmerZkproof int) (*RingPederssenParameterMessage, error) {
	if nubmerZkproof < MINIMALCHALLENGE {
		return nil, ErrTooFewChallenge
	}

	A := make([][]byte, nubmerZkproof)
	Z := make([][]byte, nubmerZkproof)
	aList := make([]*big.Int, nubmerZkproof)

	salt, err := utils.GenRandomBytes(128)
	if err != nil {
		return nil, err
	}
	for i := 0; i < nubmerZkproof; i++ {
		ai, err := utils.RandomInt(eulerValue)
		if err != nil {
			return nil, err
		}
		aList[i] = ai
		Ai := new(big.Int).Exp(t, ai, n)
		A[i] = Ai.Bytes()
	}

	hashInput := make([][]byte, 0, 5+nubmerZkproof)
	hashInput = append(hashInput, salt, ssidInfo, n.Bytes(), s.Bytes(), t.Bytes())
	hashInput = append(hashInput, A...)

	globalChallenge, err := utils.HashBytesToInt(salt, hashInput...)
	if err != nil {
		return nil, err
	}

	for i := 0; i < nubmerZkproof; i++ {
		bitVal := uint64(globalChallenge.Bit(i))
		ei := new(big.Int).SetUint64(bitVal)

		// zi = ai + ei * lambda mod φ(N)
		zi := new(big.Int).Mul(ei, lambda)
		zi.Add(aList[i], zi)
		zi.Mod(zi, eulerValue)
		Z[i] = zi.Bytes()
	}

	result := &RingPederssenParameterMessage{
		Z:    Z,
		A:    A,
		N:    n.Bytes(),
		S:    s.Bytes(),
		T:    t.Bytes(),
		Salt: salt,
	}
	return result, nil
}

func (msg *RingPederssenParameterMessage) Verify(ssidInfo []byte) error {
	verifyTime := len(msg.A)
	if verifyTime < MINIMALCHALLENGE {
		return ErrTooFewChallenge
	}
	var err error
	n := new(big.Int).SetBytes(msg.N)
	s := new(big.Int).SetBytes(msg.S)
	t := new(big.Int).SetBytes(msg.T)
	A := msg.A
	Z := msg.Z

	hashInput := make([][]byte, 0, 5+verifyTime)
	hashInput = append(hashInput, msg.Salt, ssidInfo, msg.N, msg.S, msg.T)
	hashInput = append(hashInput, A...)

	globalChallenge, err := utils.HashBytesToInt(msg.Salt, hashInput...)
	if err != nil {
		return err
	}

	for i := 0; i < verifyTime; i++ {
		Ai := new(big.Int).SetBytes(A[i])
		err = utils.InRange(Ai, big0, n)
		if err != nil {
			return err
		}
		if !utils.IsRelativePrime(Ai, n) {
			return ErrVerifyFailure
		}
		zi := new(big.Int).SetBytes(Z[i])
		err = utils.InRange(zi, big0, n)
		if err != nil {
			return err
		}

		bitVal := uint64(globalChallenge.Bit(i))
		ei := new(big.Int).SetUint64(bitVal)

		Asei := new(big.Int).Exp(s, ei, n)
		Asei.Mul(Asei, Ai)
		Asei.Mod(Asei, n)
		tzi := new(big.Int).Exp(t, zi, n)
		if tzi.Cmp(Asei) != 0 {
			return ErrVerifyFailure
		}
	}
	return nil
}
