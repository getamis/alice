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
	"errors"
	"math/big"
)

var (
	ErrInvalidMessage = errors.New("invalid message")
)

func (b *BQuadraticForm) ToMessage() *BQForm {
	return &BQForm{
		A: b.a.String(),
		B: b.b.String(),
		C: b.c.String(),
	}
}

func (bf *BQForm) ToBQuadraticForm() (*BQuadraticForm, error) {
	if bf == nil {
		return nil, ErrInvalidMessage
	}
	a, ok := new(big.Int).SetString(bf.A, 10)
	if !ok {
		return nil, ErrInvalidMessage
	}
	b, ok := new(big.Int).SetString(bf.B, 10)
	if !ok {
		return nil, ErrInvalidMessage
	}
	c, ok := new(big.Int).SetString(bf.C, 10)
	if !ok {
		return nil, ErrInvalidMessage
	}
	return NewBQuadraticForm(a, b, c)
}

func (bf *BQForm) ToCacheExp() (*cacheExp, error) {
	bq, err := bf.ToBQuadraticForm()
	if err != nil {
		return nil, err
	}
	return NewCacheExp(bq), nil
}
