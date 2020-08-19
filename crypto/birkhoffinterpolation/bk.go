// Copyright © 2020 AMIS Technologies
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

package birkhoffinterpolation

import (
	"math/big"

	"github.com/getamis/alice/crypto/utils"
)

var (
	big1 = big.NewInt(1)
)

func (p *BkParameterMessage) ToBk(fieldOrder *big.Int) (*BkParameter, error) {
	x := new(big.Int).SetBytes(p.X)
	if err := utils.InRange(x, big1, fieldOrder); err != nil {
		return nil, err
	}
	return &BkParameter{
		x:    x,
		rank: p.Rank,
	}, nil
}
