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
)

type Ed25519 struct {
	Curve

	ellipticCurve *edwards.TwistedEdwardsCurve
}

func (ed *Ed25519) IsOnCurve(x, y *big.Int) bool {
	return ed.ellipticCurve.IsOnCurve(x, y)
}

func (ed *Ed25519) Params() *elliptic.CurveParams {
	return ed.ellipticCurve.CurveParams
}

func (ed *Ed25519) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return ed.ellipticCurve.Add(x1, y1, x2, y2)
}

func (ed *Ed25519) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return ed.ellipticCurve.Double(x1, y1)
}

func (ed *Ed25519) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	return ed.ellipticCurve.ScalarMult(x1, y1, k)
}

func (ed *Ed25519) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return ed.ellipticCurve.ScalarBaseMult(k)
}

// Warn: does not deal with the original point
func (ed *Ed25519) Neg(x, y *big.Int) (*big.Int, *big.Int) {
	negativeX := new(big.Int).Neg(x)
	return negativeX.Mod(negativeX, ed.ellipticCurve.Params().P), new(big.Int).Set(y)
}

func NewEd25519() *Ed25519 {
	return &Ed25519{
		ellipticCurve: edwards.Edwards(),
	}
}
