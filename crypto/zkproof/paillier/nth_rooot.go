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
	"math/big"

	"github.com/getamis/alice/crypto/utils"
)

const NthRoot = "AMIS-Alice-NthRoot-ZK-v1.0-"

func NewNthRoot(config *CurveConfig, ssidInfo []byte, rho, rhoNPower, n *big.Int) (*NthRootMessage, error) {
	curveN := config.Curve.Params().N
	nSquare := new(big.Int).Exp(n, big2, nil)
	// Sample r in Z_{N}^ast
	r, err := utils.RandomCoprimeInt(n)
	if err != nil {
		return nil, err
	}
	// A = r^{N} mod N^2
	A := new(big.Int).Exp(r, n, nSquare)

	e, counter, err := GetE(NthRoot, curveN, utils.GetAnyMsg(ssidInfo, n.Bytes(), rhoNPower.Bytes(), A.Bytes())...)
	if err != nil {
		return nil, err
	}
	// z1 = r·ρ^e mod N_0
	z1 := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, n))
	z1.Mod(z1, n)

	return &NthRootMessage{
		Counter: counter,
		A:       A.Bytes(),
		Z1:      z1.Bytes(),
	}, nil
}

func (msg *NthRootMessage) Verify(config *CurveConfig, ssidInfo []byte, NPower, n *big.Int) error {
	curveN := config.Curve.Params().N
	nSquare := new(big.Int).Exp(n, big2, nil)

	if err := utils.InRange(NPower, big0, nSquare); err != nil {
		return err
	}
	if !utils.IsRelativePrime(NPower, n) {
		return ErrVerifyFailure
	}

	A := new(big.Int).SetBytes(msg.A)
	if err := utils.InRange(A, big0, nSquare); err != nil {
		return err
	}
	if !utils.IsRelativePrime(A, n) {
		return ErrVerifyFailure
	}

	z1 := new(big.Int).SetBytes(msg.Z1)
	if err := utils.InRange(z1, big0, n); err != nil {
		return err
	}

	msgs := utils.GetAnyMsg(ssidInfo, n.Bytes(), NPower.Bytes(), A.Bytes())
	e, expectedCounter, err := GetE(NthRoot, curveN, msgs...)
	if err != nil {
		return err
	}
	if expectedCounter != msg.Counter {
		return ErrVerifyFailure
	}

	// Check z1^n = A * NPower^e mod n^2
	ANPowerexpe := new(big.Int).Exp(NPower, e, nSquare)
	ANPowerexpe.Mul(ANPowerexpe, A)
	ANPowerexpe.Mod(ANPowerexpe, nSquare)

	compare := new(big.Int).Exp(z1, n, nSquare)
	if compare.Cmp(ANPowerexpe) != 0 {
		return ErrVerifyFailure
	}

	return nil
}