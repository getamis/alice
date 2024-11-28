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
)

const (
	CurveTypeP256 CurveType = "p256"
)

var (
	p256Curve = &p256{
		ellipticCurve: &ellipticCurve{
			Curve: elliptic.P256(),
		},
	}
)

func P256() *p256 {
	return p256Curve
}

type p256 struct {
	*ellipticCurve
}

func (c *p256) Type() CurveType {
	return CurveTypeP256
}

func (c *p256) Slip10SeedList() []byte {
	return []byte("Bitcoin seed")
}
