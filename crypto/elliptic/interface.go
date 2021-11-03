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

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
)

type Curve interface {
	elliptic.Curve

	Neg(x1, y1 *big.Int) (x, y *big.Int)
	Equal(x1, y1 *big.Int, x2, y2 *big.Int) bool
	IsIdentity(x, y *big.Int) bool
	NewIdentity() (x, y *big.Int)
	Encode(x1, y1 *big.Int) ([]byte, error)
	Decode([]byte) (*big.Int, *big.Int, error)
	Cofactor() int
	// HashToCurve()
}
