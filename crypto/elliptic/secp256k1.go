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

	"github.com/btcsuite/btcd/btcec"
)

type Secp256k1 struct {
	Curve

	ellipticCurve *btcec.KoblitzCurve
}

func (sep *Secp256k1) IsOnCurve(x, y *big.Int) bool {
	return sep.ellipticCurve.IsOnCurve(x, y)
}

func (sep *Secp256k1) Params() *elliptic.CurveParams {
	return sep.ellipticCurve.CurveParams
}

func (sep *Secp256k1) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return sep.ellipticCurve.Add(x1, y1, x2, y2)
}

func (sep *Secp256k1) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return sep.ellipticCurve.Double(x1, y1)
}

func (sep *Secp256k1) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	return sep.ellipticCurve.ScalarMult(x1, y1, k)
}

func (sep *Secp256k1) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return sep.ellipticCurve.ScalarBaseMult(k)
}

// Warn: does not deal with the original point
func (sep *Secp256k1) Neg(x, y *big.Int) (*big.Int, *big.Int) {
	NegY := new(big.Int).Neg(y)
	return new(big.Int).Set(x), NegY.Mod(NegY, sep.ellipticCurve.P)
}

func NewSecp256k1() *Secp256k1 {
	return &Secp256k1{
		ellipticCurve: btcec.S256(),
	}
}
