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

type ellipticCurve struct {
	elliptic.Curve
}

// Warn: does not deal with the original point
func (c *ellipticCurve) Neg(x, y *big.Int) (*big.Int, *big.Int) {
	NegY := new(big.Int).Neg(y)
	return new(big.Int).Set(x), NegY.Mod(NegY, c.Curve.Params().P)
}

// WARN: Only support P256 and Secp256k1
func (c *ellipticCurve) CompressedPoint(s []byte, isHash bool) []byte {
	if isHash {
		panic("Not implemented")
	}
	/* Returns the compressed bytes for this point.
	   If pt.y is odd, 0x03 is pre-pended to pt.x.
	   If pt.y is even, 0x02 is pre-pended to pt.x.
	   Returns:
	       bytes: Compressed byte representation.
	*/
	x, y := c.ScalarBaseMult(s)
	xBytePadding := x.Bytes()
	if len(x.Bytes()) < 32 {
		padding := make([]byte, 32-len(x.Bytes()))
		xBytePadding = append(padding, xBytePadding...)
	}
	if new(big.Int).And(y, big1).Cmp(big1) == 0 {
		padding := make([]byte, 1)
		padding[0] = 3
		xBytePadding = append(padding, xBytePadding...)
	} else {
		padding := make([]byte, 1)
		padding[0] = 2
		xBytePadding = append(padding, xBytePadding...)
	}
	return xBytePadding
}
