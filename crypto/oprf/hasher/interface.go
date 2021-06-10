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

package hasher

import (
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
)

//go:generate mockery -name Hasher
type Hasher interface {
	GetN() *big.Int
	Hash(input []byte) (*pt.ECPoint, error)
}
