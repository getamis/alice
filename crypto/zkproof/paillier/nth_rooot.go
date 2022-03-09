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

	e, salt, err := GetE(curveN, utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), rhoNPower.Bytes(), A.Bytes())...)
	if err != nil {
		return nil, err
	}
	// z1 = r·ρ^e mod N_0
	z1 := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, n))
	z1.Mod(z1, n)

	return &NthRootMessage{
		Salt: salt,
		A:    A.Bytes(),
		Z1:   z1.Bytes(),
	}, nil
}

func (msg *NthRootMessage) Verify(config *CurveConfig, ssidInfo []byte, NPower, n *big.Int) error {
	curveN := config.Curve.Params().N
	nSquare := new(big.Int).Exp(n, big2, nil)
	A := new(big.Int).SetBytes(msg.A)
	z1 := new(big.Int).SetBytes(msg.Z1)

	seed, err := utils.HashProtos(msg.Salt, utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(), NPower.Bytes(), A.Bytes())...)
	if err != nil {
		return err
	}

	e := utils.RandomAbsoluteRangeIntBySeed(seed, curveN)

	err = utils.InRange(e, new(big.Int).Neg(curveN), new(big.Int).Add(big1, curveN))
	if err != nil {
		return err
	}
	// Check z1^{N} = A*NPower^e mod N^2.
	ANPowerexpe := new(big.Int).Exp(NPower, e, nSquare)
	ANPowerexpe.Mul(ANPowerexpe, A)
	ANPowerexpe.Mod(ANPowerexpe, nSquare)
	compare := new(big.Int).Exp(z1, n, nSquare)
	if compare.Cmp(ANPowerexpe) != 0 {
		return ErrVerifyFailure
	}
	return nil
}
