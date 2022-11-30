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

package bulletproof

import (
	"math/big"
)

// TODO: maybe need to error handle
func InnerProduct(a, b []*big.Int, p *big.Int) *big.Int {
	result := new(big.Int).Mul(a[0], b[0])
	result.Mod(result, p)
	for i := 1; i < len(a); i++ {
		result.Add(result, new(big.Int).Mul(a[i], b[i]))
		result.Mod(result, p)
	}
	return result
}

func modP(a []*big.Int, p *big.Int) []*big.Int {
	for i := 0; i < len(a); i++ {
		a[i].Mod(a[i], p)
	}
	return a
}

func HadamardProduct(a, b []*big.Int, p *big.Int) []*big.Int {
	vec := make([]*big.Int, len(a))
	for i := 0; i < len(a); i++ {
		vec[i] = new(big.Int).Mul(a[i], b[i])
	}
	return modP(vec, p)
}

func Add(a, b []*big.Int, p *big.Int) []*big.Int {
	vec := make([]*big.Int, len(a))
	for i := 0; i < len(a); i++ {
		vec[i] = new(big.Int).Add(a[i], b[i])
	}
	return modP(vec, p)
}

func CircleDotProduct(a, b, c []*big.Int, p *big.Int) *big.Int {
	result := new(big.Int).Mul(b[0], c[0])
	result.Mod(result, p)
	result.Mul(result, a[0])
	result.Mod(result, p)
	for i := 1; i < len(a); i++ {
		temp := new(big.Int).Mul(b[i], c[i])
		temp.Mod(temp, p)
		temp.Mul(temp, a[i])
		temp.Mod(temp, p)
		result.Add(result, temp)
	}
	result.Mod(result, p)
	return result
}

func ScalarProduct(c *big.Int, a []*big.Int, p *big.Int) []*big.Int {
	vec := make([]*big.Int, len(a))
	for i := 0; i < len(a); i++ {
		vec[i] = new(big.Int).Mul(a[i], c)
	}
	return modP(vec, p)
}
