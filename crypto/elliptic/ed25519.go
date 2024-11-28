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

package elliptic

import (
	"crypto/elliptic"
	"crypto/sha512"
	"math/big"

	"filippo.io/edwards25519"

	edwards "github.com/decred/dcrd/dcrec/edwards"
)

const (
	CurveTypeEd25519 CurveType = "ed25519"
)

var (
	big1         = big.NewInt(1)
	ed25519Curve = &ed25519{
		Curve: edwards.Edwards(),
	}
)

type ed25519 struct {
	elliptic.Curve
}

func Ed25519() *ed25519 {
	return ed25519Curve
}

// Warn: does not deal with the original point
func (ed *ed25519) Neg(x, y *big.Int) (*big.Int, *big.Int) {
	negativeX := new(big.Int).Neg(x)
	return negativeX.Mod(negativeX, ed.Params().P), new(big.Int).Set(y)
}

func (ed *ed25519) Type() CurveType {
	return CurveTypeEd25519
}

func (ed *ed25519) Slip10SeedList() []byte {
	return []byte("ed25519 seed")
}

func (ed *ed25519) CompressedPoint(s *big.Int, isHash bool) []byte {
	if isHash {
		sha512 := sha512.New()
		sha512.Write(s.Bytes()[:32])
		h := sha512.Sum(nil)
		return pubKeyRFC8032Compression(h[:32])
	}
	return pubKeyRFC8032Compression(s.Bytes()[:32])
}

func pubKeyRFC8032Compression(secret []byte) []byte {
	s := edwards25519.NewScalar()
	s, _ = s.SetBytesWithClamping(secret)
	v := edwards25519.NewGeneratorPoint().ScalarMult(s, edwards25519.NewGeneratorPoint())
	return v.Bytes()
}
