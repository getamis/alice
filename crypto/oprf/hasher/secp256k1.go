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

package hasher

import (
	"crypto/elliptic"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	"golang.org/x/crypto/blake2b"
)

var (
	// The following constant only works the case Secp256k1.
	// Set Z = 1
	// 1. c1 = g(Z) = Z^3 + 7
	// 2. c2 = sqrt(-3 * Z^2)
	// 3. c3 = (sqrt(-3 * Z^2) - Z) / 2
	// 4. c4 = (sqrt(-3 * Z^2) + Z) / 2
	// 5. c5 = 1 / (3 * Z^2)
	c1    = big.NewInt(8)
	c2, _ = new(big.Int).SetString("4602937940656409685400179041082242364498080236264115595900560044423621507154", 10)
	c3, _ = new(big.Int).SetString("60197513588986302554485582024885075108884032450952339817679072026166228089408", 10)
	c4, _ = new(big.Int).SetString("60197513588986302554485582024885075108884032450952339817679072026166228089409", 10)
	c5, _ = new(big.Int).SetString("77194726158210796949047323339125271902179989777093709359638389338605889781109", 10)

	// big1 is big int 1
	big1 = big.NewInt(1)
	// big2 is big int 2
	big2 = big.NewInt(2)
	// big3 is big int 3
	big3 = big.NewInt(3)

	// The times of max retry
	maxRetry = 100
)

type secp256k1 struct {
	curve elliptic.Curve
}

func NewSECP256k1() Hasher {
	return &secp256k1{
		curve: btcec.S256(),
	}
}

func (s *secp256k1) GetN() *big.Int {
	return s.curve.Params().N
}

// Section 6.9.1.  Shallue-van de Woestijne Method: Hashing to Elliptic Curves: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.9.1
//Steps:
//  1.   t1 = u^2
//  2.   t2 = t1 + c1           // t2 = u^2 + g(Z)
//  3.   t3 = t1 * t2
//  4.   t4 = inv0(t3)          // t4 = 1 / (u^2 * (u^2 + g(Z)))
//  5.   t3 = t1^2
//  6.   t3 = t3 * t4
//  7.   t3 = t3 * c2           // t3 = u^2 * sqrt(-3 * Z^2) / (u^2 + g(Z))
//  8.   x1 = c3 - t3
//  9.  gx1 = x1^2
//  10. gx1 = gx1 * x1
//  11. gx1 = gx1 + B           // gx1 = x1^3 + B
//  12.  e1 = is_square(gx1)
//  13.  x2 = t3 - c4
//  14. gx2 = x2^2
//  15. gx2 = gx2 * x2
//  16. gx2 = gx2 + B           // gx2 = x2^3 + B
//  17.  e2 = is_square(gx2)
//  18.  e3 = e1 OR e2          // logical OR
//  19.  x3 = t2^2
//  20.  x3 = x3 * t2
//  21.  x3 = x3 * t4
//  22.  x3 = x3 * c5
//  23.  x3 = Z - x3            // Z - (u^2 + g(Z))^2 / (3 Z^2 u^2)
//  24. gx3 = x3^2
//  25. gx3 = gx3 * x3
//  26. gx3 = gx3 + B           // gx3 = x3^3 + B
//  27.   x = CMOV(x2, x1, e1)  // select x1 if gx1 is square
//  28.  gx = CMOV(gx2, gx1, e1)
//  29.   x = CMOV(x3, x, e3)   // select x3 if gx1 and gx2 are not square
//  30.  gx = CMOV(gx3, gx, e3)
//  31.   y = sqrt(gx)
//  32.  e4 = sgn0(u) == sgn0(y)
//  33.   y = CMOV(-y, y, e4)   // select correct sign of y
func (s *secp256k1) Hash(pw []byte) (*pt.ECPoint, error) {
	fieldOrder := s.curve.Params().P
	u, err := getHashValueByRejectSampling(pw, fieldOrder)
	if err != nil {
		return nil, err
	}
	t1 := new(big.Int).Exp(u, big2, fieldOrder)
	t2 := new(big.Int).Add(t1, c1)
	t3 := new(big.Int).Mul(t1, t2)
	t3 = t3.Mod(t3, fieldOrder)
	t4 := new(big.Int).ModInverse(t3, fieldOrder)
	t3 = t3.Exp(t1, big2, fieldOrder)
	t3 = t3.Mul(t3, t4)
	t3 = t3.Mul(t3, c2)
	t3 = t3.Mod(t3, fieldOrder)
	x1 := new(big.Int).Sub(c3, t3)
	x1 = x1.Mod(x1, fieldOrder)
	gx1 := new(big.Int).Exp(x1, big3, fieldOrder)
	gx1 = gx1.Add(gx1, s.curve.Params().B)
	gx1 = gx1.Mod(gx1, fieldOrder)
	e1 := isSquare(gx1, fieldOrder)
	x2 := new(big.Int).Sub(t3, c4)
	x2 = x2.Mod(x2, fieldOrder)
	gx2 := new(big.Int).Exp(x2, big3, fieldOrder)
	gx2 = gx2.Add(gx2, s.curve.Params().B)
	gx2 = gx2.Mod(gx2, fieldOrder)
	e2 := isSquare(gx2, fieldOrder)
	e3 := e1 || e2
	x3 := new(big.Int).Exp(t2, big3, fieldOrder)
	x3 = x3.Mul(x3, t4)
	x3 = x3.Mul(x3, c5)
	x3 = x3.Sub(big1, x3)
	x3 = x3.Mod(x3, fieldOrder)
	gx3 := new(big.Int).Exp(x3, big3, fieldOrder)
	gx3 = gx3.Add(gx3, s.curve.Params().B)
	gx3 = gx3.Mod(gx3, fieldOrder)
	x := cmov(x2, x1, e1)
	gx := cmov(gx2, gx1, e1)
	x = cmov(x3, x, e3)
	gx = cmov(gx3, gx, e3)
	y := new(big.Int).ModSqrt(gx, fieldOrder)
	e4 := u.Sign() == y.Sign()
	y = cmov(y, y.Neg(y), e4)
	y = y.Mod(y, fieldOrder)
	return pt.NewECPoint(s.curve, x, y)
}

// Not constant time
func cmov(a, b *big.Int, c bool) *big.Int {
	if c {
		return new(big.Int).Set(b)
	}
	return new(big.Int).Set(a)
}

// Get the hash value of pw by rejectSampling
func getHashValueByRejectSampling(pw []byte, fieldOrder *big.Int) (*big.Int, error) {
	hashPW := pw
	for i := 0; i < maxRetry; i++ {
		hashPWC := blake2b.Sum256(hashPW)
		hashPW = hashPWC[:]
		hashValue := new(big.Int).SetBytes(hashPW)
		if utils.InRange(hashValue, big1, fieldOrder) == nil {
			return hashValue, nil
		}
	}
	return nil, utils.ErrExceedMaxRetry
}

// isSquare x^2 = a mod fieldOrder
func isSquare(a *big.Int, fieldOrder *big.Int) bool {
	return big.Jacobi(a, fieldOrder) != -1
}
