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
package binaryquadraticform

import (
	"math/big"
)

type cacheExp struct {
	bq *BQuadraticForm

	cache []*BQuadraticForm
}

// NewCacheExp initiates a cache BQ exp. In this struct, we calculate exp by cached values
func NewCacheExp(bq *BQuadraticForm) *cacheExp {
	return &cacheExp{
		bq:    bq,
		cache: []*BQuadraticForm{},
	}
}

func (c *cacheExp) Exp(power *big.Int) (*BQuadraticForm, error) {
	r := c.bq.Identity()
	if power.Cmp(big0) == 0 {
		return r, nil
	}

	// Ensure the length of cache is over power.BitLen()
	err := c.buildCache(power.BitLen())
	if err != nil {
		return nil, err
	}

	for i := 0; i < power.BitLen(); i++ {
		if power.Bit(i) != 0 {
			r, err = r.Composition(c.cache[i])
			if err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

func (c *cacheExp) buildCache(lens int) error {
	current := len(c.cache)
	// Check id the cache is enough
	if current >= lens {
		return nil
	}

	var cache *BQuadraticForm
	if current == 0 {
		// If the cache is empty, create an init one
		cache = c.bq.Copy()
		c.cache = append(c.cache, cache)
		current++
	} else {
		cache = c.cache[current-1]
	}

	var err error
	for i := current; i < lens; i++ {
		cache, err = cache.square()
		if err != nil {
			return err
		}
		c.cache = append(c.cache, cache)
	}
	return nil
}

func (c *cacheExp) ToMessage() *BQForm {
	return c.bq.ToMessage()
}
