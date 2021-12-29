// Copyright © 2021 AMIS Technologies
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

package elliptic

import (
	"crypto/elliptic"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/gtank/ristretto255"
)

var (
	ellipticCurve = edwards.Edwards()
)

type SR25519 struct {
	Parameter *elliptic.CurveParams
	Curve
	H int // Cofactor
}

func (sr *SR25519) IsOnCurve(x, y *big.Int) bool {
	return ellipticCurve.IsOnCurve(x, y)
}

func (sr *SR25519) Params() *elliptic.CurveParams {
	return sr.Parameter
}

func (sr *SR25519) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return ellipticCurve.Add(x1, y1, x2, y2)
}

func (sr *SR25519) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return ellipticCurve.Double(x1, y1)
}

func (sr *SR25519) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	return ellipticCurve.ScalarMult(x1, y1, k)
}

func (sr *SR25519) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return ellipticCurve.ScalarBaseMult(k)
}

// Warn: does not deal with the original point
func (sr *SR25519) Neg(x, y *big.Int) (*big.Int, *big.Int) {
	negativeX := new(big.Int).Neg(x)
	return negativeX.Mod(negativeX, ellipticCurve.Params().P), new(big.Int).Set(y)
}

func (sr *SR25519) Equal(x1, y1, x2, y2 *big.Int) bool {
	isOnCurve1 := sr.IsOnCurve(x1, y1)
	isOnCurve2 := sr.IsOnCurve(x2, y2)
	if !isOnCurve1 || !isOnCurve2 {
		return false
	}
	pt1, err := ristretto255.ToExtendedProjectveCoordinate(x1, y1)
	if err != nil {
		return false
	}
	pt2, err := ristretto255.ToExtendedProjectveCoordinate(x2, y2)
	if err != nil {
		return false
	}
	return pt1.Equal(pt2) == 1
}

func (sr *SR25519) IsIdentity(x, y *big.Int) bool {
	pt, err := ristretto255.ToExtendedProjectveCoordinate(x, y)
	if err != nil {
		return false
	}
	identity, err := ristretto255.ToExtendedProjectveCoordinate(big0, big1)
	if err != nil {
		return false
	}
	return pt.Equal(identity) == 1
}

func (sr *SR25519) NewIdentity() (*big.Int, *big.Int) {
	return big.NewInt(0), big.NewInt(1)
}

func (sr *SR25519) Encode(x *big.Int, y *big.Int) ([]byte, error) {
	pt, err := ristretto255.ToExtendedProjectveCoordinate(x, y)
	if err != nil {
		return nil, err
	}
	return pt.Bytes(), nil
}

func (sr *SR25519) Decode(input []byte) (*big.Int, *big.Int, error) {
	pt := ristretto255.NewElement()
	err := pt.Decode(input)
	if err != nil {
		return nil, nil, err
	}
	x, y := pt.ToAffineCoordinate()
	return x, y, nil
}

func (sr *SR25519) Cofactor() int {
	return sr.H
}

// InitParam25519 initializes an instance of the Ed25519 curve.
func (sr *SR25519) InitParamSR25519() {
	// The prime modulus of the field.
	// P = 2^255-19
	tempParameter := new(elliptic.CurveParams)
	tempParameter.P = new(big.Int)
	tempParameter.P.SetBit(big0, 255, 1).Sub(tempParameter.P, big.NewInt(19))

	// The prime order for the base point.
	// N = 2^252 + 27742317777372353535851937790883648493
	qs, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	tempParameter.N = new(big.Int)
	tempParameter.N.SetBit(big0, 252, 1).Add(tempParameter.N, qs) // AKA Q

	// The base point.
	tempParameter.Gx = new(big.Int)
	tempParameter.Gx.SetString("151122213495354007725011514095885315"+
		"11454012693041857206046113283949847762202", 10)
	tempParameter.Gy = new(big.Int)
	tempParameter.Gy.SetString("463168356949264781694283940034751631"+
		"41307993866256225615783033603165251855960", 10)

	tempParameter.BitSize = 256
	sr.H = 1
	sr.Parameter = tempParameter
}

// WARN: Cofactor should be 1
func NewSR25519() *SR25519 {
	c := new(SR25519)
	c.InitParamSR25519()
	return c
}
