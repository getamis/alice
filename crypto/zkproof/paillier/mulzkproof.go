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

func NewMulMessage(ssidInfo []byte, x, rho, rhox, N, X, Y, C, fieldOrder *big.Int) (*MulMessage, error) {
	alpha, err := utils.RandomCoprimeInt(N)
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomCoprimeInt(N)
	if err != nil {
		return nil, err
	}
	s, err := utils.RandomCoprimeInt(N)
	if err != nil {
		return nil, err
	}
	NSquare := new(big.Int).Mul(N, N)
	A := new(big.Int).Exp(Y, alpha, NSquare)
	A.Mul(A, new(big.Int).Exp(r, N, NSquare))
	A.Mod(A, NSquare)

	B := new(big.Int).Exp(new(big.Int).Add(big1, N), alpha, NSquare)
	B.Mul(B, new(big.Int).Exp(s, N, NSquare))
	B.Mod(B, NSquare)

	e, salt, err := GetE(fieldOrder, utils.GetAnyMsg(ssidInfo, A.Bytes(), B.Bytes(), N.Bytes(), X.Bytes(), Y.Bytes(), C.Bytes())...)
	if err != nil {
		return nil, err
	}

	z := new(big.Int).Add(alpha, new(big.Int).Mul(e, x))
	u := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, N))
	u.Mod(u, N)
	v := new(big.Int).Mul(s, new(big.Int).Exp(rhox, e, N))
	v.Mod(v, N)
	return &MulMessage{
		Salt: salt,
		A:    A.Bytes(),
		B:    B.Bytes(),
		Z:    z.String(),
		U:    u.Bytes(),
		V:    v.Bytes(),
	}, nil

}

func (msg *MulMessage) Verify(ssidInfo []byte, N, X, Y, C, fieldOrder *big.Int) error {
	seed, err := utils.HashProtos(msg.Salt, utils.GetAnyMsg(ssidInfo, msg.A, msg.B, N.Bytes(), X.Bytes(), Y.Bytes(), C.Bytes())...)
	if err != nil {
		return err
	}
	e := utils.RandomAbsoluteRangeIntBySeed(seed, fieldOrder)
	err = utils.InRange(e, new(big.Int).Neg(fieldOrder), new(big.Int).Add(big1, fieldOrder))
	if err != nil {
		return err
	}
	z, _ := new(big.Int).SetString(msg.Z, 10)
	u := new(big.Int).SetBytes(msg.U)
	v := new(big.Int).SetBytes(msg.V)
	A := new(big.Int).SetBytes(msg.A)
	B := new(big.Int).SetBytes(msg.B)

	NSquare := new(big.Int).Mul(N, N)
	YExpZuExpN := new(big.Int).Exp(Y, z, NSquare)
	YExpZuExpN = YExpZuExpN.Mul(YExpZuExpN, new(big.Int).Exp(u, N, NSquare))
	YExpZuExpN.Mod(YExpZuExpN, NSquare)
	ACExpE := new(big.Int).Mul(A, new(big.Int).Exp(C, e, NSquare))
	ACExpE.Mod(ACExpE, NSquare)
	if ACExpE.Cmp(YExpZuExpN) != 0 {
		return ErrVerifyFailure
	}

	oneAddNExpzCExpN := new(big.Int).Exp(new(big.Int).Add(big1, N), z, NSquare)
	oneAddNExpzCExpN.Mul(oneAddNExpzCExpN, new(big.Int).Exp(v, N, NSquare))
	oneAddNExpzCExpN.Mod(oneAddNExpzCExpN, NSquare)
	BXExpE := new(big.Int).Mul(B, new(big.Int).Exp(X, e, NSquare))
	BXExpE.Mod(BXExpE, NSquare)
	if oneAddNExpzCExpN.Cmp(BXExpE) != 0 {
		return ErrVerifyFailure
	}
	return nil
}
