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
	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	CurveTypeSecp256k1 CurveType = "secp256k1"
)

var (
	secp256k1Curve = &secp256k1{
		ellipticCurve: &ellipticCurve{
			Curve: btcec.S256(),
		},
	}
)

func Secp256k1() *secp256k1 {
	return secp256k1Curve
}

type secp256k1 struct {
	*ellipticCurve
}

func (c *secp256k1) Type() CurveType {
	return CurveTypeSecp256k1
}

func (c *secp256k1) Slip10SeedList() []byte {
	return []byte("Bitcoin seed")
}
