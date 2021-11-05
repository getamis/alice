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
)

const (
	BIGLENGTHP = 48
)

type P384 struct {
	Curve
	H int // Cofactor

	ellipticCurve elliptic.Curve
}

func (p *P384) IsOnCurve(x, y *big.Int) bool {
	return p.ellipticCurve.IsOnCurve(x, y)
}

func (p *P384) Params() *elliptic.CurveParams {
	return p.ellipticCurve.Params()
}

func (p *P384) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return p.ellipticCurve.Add(x1, y1, x2, y2)
}

func (p *P384) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return p.ellipticCurve.Double(x1, y1)
}

func (p *P384) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	return p.ellipticCurve.ScalarMult(x1, y1, k)
}

func (p *P384) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return p.ellipticCurve.ScalarBaseMult(k)
}

// Warn: does not deal with the original point
func (p *P384) Neg(x, y *big.Int) (*big.Int, *big.Int) {
	NegY := new(big.Int).Neg(y)
	return new(big.Int).Set(x), NegY.Mod(NegY, p.ellipticCurve.Params().P)
}

func (p *P384) Equal(x1, y1, x2, y2 *big.Int) bool {
	if x1 == nil || x2 == nil || y1 == nil || y2 == nil {
		return false
	}
	if p.IsIdentity(x1, y1) && p.IsIdentity(x2, y2) {
		return true
	}
	isOnCurve1 := p.IsOnCurve(x1, y1)
	isOnCurve2 := p.IsOnCurve(x2, y2)
	if !isOnCurve1 || !isOnCurve2 {
		return false
	}
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return true
	}
	return false
}

func (p *P384) IsIdentity(x, y *big.Int) bool {
	return x.Cmp(big0) == 0 && y.Cmp(big0) == 0
}

func (p *P384) NewIdentity() (*big.Int, *big.Int) {
	return big.NewInt(0), big.NewInt(0)
}

func (p *P384) Encode(x *big.Int, y *big.Int) ([]byte, error) {
	if x.Cmp(p.Params().P) > 0 || y.Cmp(p.Params().P) > 0 {
		return nil, ErrInvalidPoint
	}
	// 48 = 384/8 (i.e. the bit length of para.P)
	xByte := x.FillBytes(make([]byte, BIGLENGTHP))
	yByte := y.FillBytes(make([]byte, BIGLENGTHP))
	return append(xByte, yByte...), nil
}

func (p *P384) Cofactor() int {
	return p.H
}

func (p *P384) Decode(input []byte) (*big.Int, *big.Int, error) {
	// 96 = BIGLENGTHP*2
	if len(input) != 96 {
		return nil, nil, ErrInvalidPoint
	}

	return new(big.Int).SetBytes(input[0:BIGLENGTHP]), new(big.Int).SetBytes(input[BIGLENGTHP:]), nil
}

// WARN: Cofactor should be 1
func NewP384() *P384 {
	return &P384{
		H:             1,
		ellipticCurve: elliptic.P384(),
	}
}
