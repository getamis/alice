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
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/btcsuite/btcd/btcec"
)

var (
	// ErrInvalidPoint is returned if the point is invalid.
	ErrInvalidPoint = errors.New("invalid point")
	// ErrDifferentCurve is returned if the two different elliptic curves.
	ErrDifferentCurve = errors.New("different elliptic curves")
	// ErrInvalidCurve is returned if the curve is invalid.
	ErrInvalidCurve = errors.New("invalid curve")
)

// ECPoint is the struct for an elliptic curve point.
type ECPoint struct {
	curve elliptic.Curve
	x     *big.Int
	y     *big.Int
}

// NewECPoint creates an EC-Point and verifies that it should locate on the given elliptic curve.
// Note: when x = nil, y =nil, we set it to be the identity element in the elliptic curve group.
func NewECPoint(curve elliptic.Curve, x *big.Int, y *big.Int) (*ECPoint, error) {
	if !isOnCurve(curve, x, y) {
		return nil, ErrInvalidPoint
	}
	if isIdentity(x, y) {
		return NewIdentity(curve), nil
	}
	return &ECPoint{
		curve: curve,
		x:     new(big.Int).Set(x),
		y:     new(big.Int).Set(y),
	}, nil
}

// NewIdentity returns the identity element of the given elliptic curve.
func NewIdentity(curve elliptic.Curve) *ECPoint {
	return &ECPoint{
		curve: curve,
		x:     nil,
		y:     nil,
	}
}

// NewBase returns the base point of the given elliptic curve.
func NewBase(curve elliptic.Curve) *ECPoint {
	p := curve.Params()
	return &ECPoint{
		curve: curve,
		x:     p.Gx,
		y:     p.Gy,
	}
}

// IsIdentity checks if the point is the identity element.
func (p *ECPoint) IsIdentity() bool {
	return isIdentity(p.x, p.y)
}

// ToPubKey returns pubkey
func (p *ECPoint) ToPubKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.curve,
		X:     new(big.Int).Set(p.x),
		Y:     new(big.Int).Set(p.y),
	}
}

// String returns the string format of the point.
func (p *ECPoint) String() string {
	return fmt.Sprintf("(x, y) =(%s, %s)", p.x, p.y)
}

// Add sums up two arbitrary points located on the same elliptic curve.
func (p *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	if !isSameCurve(p.curve, p1.curve) {
		return nil, ErrDifferentCurve
	}
	if !isOnCurve(p.curve, p.x, p.y) {
		return nil, ErrInvalidPoint
	}
	if !isOnCurve(p1.curve, p1.x, p1.y) {
		return nil, ErrInvalidPoint
	}
	if p.IsIdentity() {
		return p1.Copy(), nil
	}
	if p1.IsIdentity() {
		return p.Copy(), nil
	}

	// The case : aG+(-a)G. Assume that the coordinate of aG = (x,y). Then (-a)G = (x,-y). Then aG + (-a)G = identity = (nil, nil).
	if p1.x.Cmp(p.x) == 0 {
		tempNegative := new(big.Int).Neg(p1.y)
		tempNegative.Mod(tempNegative, p.curve.Params().P)
		if tempNegative.Cmp(p.y) == 0 {
			return NewIdentity(p.curve), nil
		}
	}
	// The case : aG + aG = 2aG.
	if p1.x.Cmp(p.x) == 0 && p1.y.Cmp(p.y) == 0 {
		return p1.ScalarMult(big2), nil
	}
	// The sum of the other cases
	x, y := p.curve.Add(p.x, p.y, p1.x, p1.y)
	return NewECPoint(p.curve, x, y)
}

// ScalarMult multiplies the point k times. If the point is the identity element, do nothing.
func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	kModN := new(big.Int).Mod(k, p.curve.Params().N)
	if p.IsIdentity() || kModN.Cmp(big0) == 0 {
		return NewIdentity(p.curve)
	}
	newX, newY := p.curve.ScalarMult(p.x, p.y, kModN.Bytes())
	return &ECPoint{
		curve: p.curve,
		x:     newX,
		y:     newY,
	}
}

func (p *ECPoint) Neg() *ECPoint {
	if p.IsIdentity() {
		return NewIdentity(p.curve)
	}
	negativeY := new(big.Int).Neg(p.y)
	negativeY = negativeY.Mod(negativeY, p.curve.Params().P)
	return &ECPoint{
		curve: p.curve,
		x:     new(big.Int).Set(p.x),
		y:     negativeY,
	}
}

// GetX returns the x coordinate of the point.
func (p *ECPoint) GetX() *big.Int {
	if p.IsIdentity() {
		return nil
	}
	return new(big.Int).Set(p.x)
}

// GetY returns the x coordinate of the point.
func (p *ECPoint) GetY() *big.Int {
	if p.IsIdentity() {
		return nil
	}
	return new(big.Int).Set(p.y)
}

// GetCurve returns the elliptic curve of the point.
func (p *ECPoint) GetCurve() elliptic.Curve {
	return p.curve
}

// IsSameCurve checks if the point is on the same curve with the given point.
func (p *ECPoint) IsSameCurve(p2 *ECPoint) bool {
	return isSameCurve(p.curve, p2.curve)
}

// Copy copies the point.
func (p *ECPoint) Copy() *ECPoint {
	if p.IsIdentity() {
		return NewIdentity(p.curve)
	}
	return &ECPoint{
		curve: p.curve,
		x:     new(big.Int).Set(p.x),
		y:     new(big.Int).Set(p.y),
	}
}

// Equal checks if the point is the same with the given point.
func (p *ECPoint) Equal(p1 *ECPoint) bool {
	return reflect.DeepEqual(p, p1)
}

// ToEcPointMessage converts the point to proto message.
func (p *ECPoint) ToEcPointMessage() (*EcPointMessage, error) {
	curveType, err := ToCurve(p.curve)
	if err != nil {
		return nil, err
	}
	if p.IsIdentity() {
		return &EcPointMessage{
			Curve: curveType,
		}, nil
	}
	return &EcPointMessage{
		Curve: curveType,
		X:     p.x.Bytes(),
		Y:     p.y.Bytes(),
	}, nil
}

// ToPoint converts the point from proto message.
func (p *EcPointMessage) ToPoint() (*ECPoint, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}
	curve, err := p.Curve.GetEllipticCurve()
	if err != nil {
		return nil, err
	}

	if len(p.X) == 0 && len(p.Y) == 0 {
		return NewIdentity(curve), nil
	}

	return NewECPoint(curve, new(big.Int).SetBytes(p.X), new(big.Int).SetBytes(p.Y))
}

func isIdentity(x *big.Int, y *big.Int) bool {
	if x == nil && y == nil {
		return true
	}
	return false
}

func isSameCurve(curve1 elliptic.Curve, curve2 elliptic.Curve) bool {
	return reflect.DeepEqual(curve1, curve2)
}

func isOnCurve(curve elliptic.Curve, x, y *big.Int) bool {
	// The identity element belongs to the elliptic curve group.
	if x == nil && y == nil {
		return true
	}
	if x == nil || y == nil {
		return false
	}
	return curve.IsOnCurve(x, y)
}

func (c EcPointMessage_Curve) GetEllipticCurve() (elliptic.Curve, error) {
	switch c {
	case EcPointMessage_P224:
		return elliptic.P224(), nil
	case EcPointMessage_P256:
		return elliptic.P256(), nil
	case EcPointMessage_P384:
		return elliptic.P384(), nil
	case EcPointMessage_S256:
		return btcec.S256(), nil
	}
	return nil, ErrInvalidCurve
}

func ToCurve(c elliptic.Curve) (EcPointMessage_Curve, error) {
	switch c {
	case elliptic.P224():
		return EcPointMessage_P224, nil
	case elliptic.P256():
		return EcPointMessage_P256, nil
	case elliptic.P384():
		return EcPointMessage_P384, nil
	case btcec.S256():
		return EcPointMessage_S256, nil
	}
	return 0, ErrInvalidCurve
}
