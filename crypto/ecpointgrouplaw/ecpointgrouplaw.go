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

package ecpointgrouplaw

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

var (
	// ErrDifferentLength is returned if the two slices has different lengths.
	ErrDifferentLength = errors.New("different lengths of slices")
	// ErrEmptySlice is returned if the length of slice is zero.
	ErrEmptySlice = errors.New("the length of slice is zero")

	// big0 is big int 0
	big0 = big.NewInt(0)
	// big1 is big int 1
	big1 = big.NewInt(1)
	// big2 is big int 2
	big2 = big.NewInt(2)
)

// ScalarBaseMult multiplies the base point k times.
func ScalarBaseMult(c elliptic.Curve, k *big.Int) *ECPoint {
	baseScalarPoint := NewBase(c).ScalarMult(k)
	return baseScalarPoint
}

// ComputeLinearCombinationPoint returns the linear combination of points by multiplying scalar.
// Give two arrays: [a1,a2,a3] and points in secp256k1 [G1,G2,G3]. The outcome of this function is a1*G1+a2*G2+a3*G3.
// Ex: Give two arrays: [1,2,5] and points in secp256k1 [G1,G2,G3]. The outcome of this function is 1*G1+2*G2+5*G3.
func ComputeLinearCombinationPoint(scalar []*big.Int, points []*ECPoint) (*ECPoint, error) {
	if len(scalar) == 0 {
		return nil, ErrEmptySlice
	}
	if len(scalar) != len(points) {
		return nil, ErrDifferentLength
	}
	var err error
	result := NewIdentity(points[0].curve)
	for i := 0; i < len(scalar); i++ {
		result, err = result.Add(points[i].ScalarMult(scalar[i]))
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
