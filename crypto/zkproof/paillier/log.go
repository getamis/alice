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

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/ptypes/any"
)

func NewLog(ssidInfo []byte, x *big.Int, g, h, X, Y *pt.ECPoint) (*LogMessage, error) {
	curveN := g.GetCurve().Params().N
	alpha, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}
	// A = alpha*g, B = alpha*h
	A := g.ScalarMult(alpha)
	B := h.ScalarMult(alpha)

	msgG, err := g.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgh, err := h.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgA, err := A.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgB, err := B.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgX, err := X.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msgY, err := Y.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	e, salt, err := utils.HashProtosRejectSampling(curveN, &any.Any{
		Value: ssidInfo,
	}, msgA, msgB, msgG, msgX, msgY, msgh,
	)
	if err != nil {
		return nil, err
	}
	// z = α+ex
	z := new(big.Int).Add(alpha, new(big.Int).Mul(e, x))
	z.Mod(z, curveN)

	return &LogMessage{
		Salt: salt,
		A:    msgA,
		B:    msgB,
		Z:    z.Bytes(),
	}, nil
}

func (msg *LogMessage) Verify(ssidInfo []byte, g, h, X, Y *pt.ECPoint) error {
	curveN := g.GetCurve().Params().N
	z := new(big.Int).SetBytes(msg.Z)
	A, err := msg.A.ToPoint()
	if err != nil {
		return err
	}
	B, err := msg.B.ToPoint()
	if err != nil {
		return err
	}
	msgG, err := g.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgh, err := h.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgX, err := X.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgY, err := Y.ToEcPointMessage()
	if err != nil {
		return err
	}

	e, err := utils.HashProtosToInt(msg.Salt, &any.Any{
		Value: ssidInfo,
	}, msg.A, msg.B, msgG, msgX, msgY, msgh,
	)
	if err != nil {
		return err
	}
	err = utils.InRange(e, big0, curveN)
	if err != nil {
		return err
	}

	// Check z*G = A+e*X and z*h = B+e*Y
	zG := g.ScalarMult(z)
	compare := X.ScalarMult(e)
	compare, err = A.Add(compare)
	if err != nil {
		return err
	}
	if !compare.Equal(zG) {
		return ErrVerifyFailure
	}
	zh := h.ScalarMult(z)
	compare = Y.ScalarMult(e)
	compare, err = compare.Add(B)
	if err != nil {
		return err
	}
	if !compare.Equal(zh) {
		return ErrVerifyFailure
	}

	return nil
}
