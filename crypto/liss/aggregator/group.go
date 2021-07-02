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

package aggregator

import (
	"errors"

	bqForm "github.com/getamis/alice/crypto/binaryquadraticform"
	liss "github.com/getamis/alice/crypto/liss"
)

var (
	ErrNotEnoughUserResults = errors.New("not enough user results")
)

type Cipertext map[string]*bqForm.BQuadraticForm

func (c Cipertext) Has(key string) bool {
	_, ok := c[key]
	return ok
}

func (c Cipertext) Len() int {
	return len(c)
}

type Group struct {
	*liss.GroupConfig

	UserResults []map[string]*bqForm.BQuadraticForm
}

func (g *Group) Add(userIndex int, partialCiphertext Cipertext) bool {
	if !g.CheckKeys(userIndex, partialCiphertext) {
		return false
	}
	g.UserResults[userIndex] = partialCiphertext
	return true
}

func (g *Group) IsEnough() bool {
	count := 0
	for _, u := range g.UserResults {
		if u != nil {
			count++
		}
	}
	return count >= g.Threshold
}

func (g *Group) GetComposition() (*bqForm.BQuadraticForm, error) {
	if !g.IsEnough() {
		return nil, ErrNotEnoughUserResults
	}

	// Collect the first Threshold results
	var indexes []int
	for i, u := range g.UserResults {
		if u == nil {
			continue
		}
		indexes = append(indexes, i)
		if len(indexes) >= g.Threshold {
			break
		}
	}

	// Compose the user results
	key := liss.ShareKey(indexes)
	c1 := g.UserResults[indexes[0]][key]
	for i := 1; i < len(indexes); i++ {
		tmp := g.UserResults[indexes[i]][key].Inverse()
		var err error
		c1, err = c1.Composition(tmp)
		if err != nil {
			return nil, err
		}
	}
	return c1, nil
}
