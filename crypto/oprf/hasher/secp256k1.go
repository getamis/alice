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
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	"golang.org/x/crypto/blake2b"
)

var (
	/* The following constant only works the case Secp256k1.
	   Set Z = 1
	   1. c1 = g(Z)
	   2. c2 = -Z / 2
	   3. c3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A)) # sgn0(c3) MUST equal 0
	   4. c4 = -4 * g(Z) / (3 * Z^2 + 4 * A) */
	c1    = big.NewInt(8)
	c2, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003954417335831", 10)
	c3, _ = new(big.Int).SetString("10388779673325959979325452626823788324994718367665745800388075445979975427086", 10)
	c4, _ = new(big.Int).SetString("77194726158210796949047323339125271902179989777093709359638389338605889781098", 10)

	// big0 is big int 0
	big0 = big.NewInt(0)
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
// Not constant time
func cmov(a, b *big.Int, c bool) *big.Int {
	if c {
		return new(big.Int).Set(b)
	}
	return new(big.Int).Set(a)
}

// Get the hash value of pw by rejectSampling.
// Note: Reject Sampling does Not recommend. Because it is not constant time.
// But in secp256k1, the possibility of regerneration is very low.
func getHashValueByRejectSampling(hashPW []byte, fieldOrder *big.Int) (*big.Int, error) {
	for i := 0; i < maxRetry; i++ {
		hash256Value := new(big.Int).SetBytes(hashPW)
		if utils.InRange(hash256Value, big0, fieldOrder) == nil {
			return hash256Value, nil
		}
		hashPWC := sha256.Sum256(hashPW)
		hashPW = hashPWC[:]
	}
	return nil, utils.ErrExceedMaxRetry
}

// isSquare x^2 = a mod fieldOrder
func isSquare(a *big.Int, fieldOrder *big.Int) bool {
	return big.Jacobi(a, fieldOrder) != -1
}

// The result comes from two hash functions. ref: https://eprint.iacr.org/2009/340.pdf
func (s *secp256k1) Hash(pw []byte) (*pt.ECPoint, error) {
	fieldOrder := s.curve.Params().P
	hashblake2b := blake2b.Sum256(pw)
	hash256PWC := sha256.Sum256(pw)
	u1, err := getHashValueByRejectSampling(hashblake2b[:], fieldOrder)
	if err != nil {
		return nil, err
	}
	blake2bResult, err := hash(u1, s.curve)
	if err != nil {
		return nil, err
	}

	u2, err := getHashValueByRejectSampling(hash256PWC[:], fieldOrder)
	sha256Result, err := hash(u2, s.curve)
	if err != nil {
		return nil, err
	}
	return sha256Result.Add(blake2bResult)
}

// ref: 6.6.1. Shallue-van de Woestijne Method in https://tools.ietf.org/pdf/draft-irtf-cfrg-hash-to-curve-07.pdf
/* Steps:
1. tv1 = u^2
2. tv1 = tv1 * c1
3. tv2 = 1 + tv1
4. tv1 = 1 - tv1
5. tv3 = tv1 * tv2
6. tv3 = inv0(tv3)
7. tv4 = u * tv1
8. tv4 = tv4 * tv3
9. tv4 = tv4 * c3
10. x1 = c2 - tv4
11. gx1 = x1^2
12. gx1 = gx1 + A
13. gx1 = gx1 * x1
14. gx1 = gx1 + B
15. e1 = is_square(gx1)
16. x2 = c2 + tv4
17. gx2 = x2^2
18. gx2 = gx2 + A
19. gx2 = gx2 * x2
20. gx2 = gx2 + B
21. e2 = is_square(gx2) AND NOT e1
22. x3 = tv2^2
23. x3 = x3 * tv3
24. x3 = x3^2
25. x3 = x3 * c4
26. x3 = x3 + Z
27. x = CMOV(x3, x1, e1)
28. x = CMOV(x, x2, e2)
29. gx = x^2
30. gx = gx + A
31. gx = gx * x
32. gx = gx + B
33. y = sqrt(gx)
34. e3 = sgn0(u) == sgn0(y)
35. y = CMOV(-y, y, e3)
36. return (x, y) */
func hash(u *big.Int, curve elliptic.Curve) (*pt.ECPoint, error) {
	fieldOrder := curve.Params().P
	t1 := new(big.Int).Exp(u, big2, fieldOrder)
	t1.Mul(t1, c1)
	t2 := new(big.Int).Add(big1, t1)
	t1.Sub(big1, t1)
	t1.Mod(t1, fieldOrder)
	t3 := new(big.Int).Mul(t1, t2)
	t3.ModInverse(t3, fieldOrder)
	t4 := new(big.Int).Mul(u, t1)
	t4.Mul(t4, t3)
	t4.Mul(t4, c3)
	x1 := new(big.Int).Sub(c2, t4)
	x1.Mod(x1, fieldOrder)
	gx1 := new(big.Int).Exp(x1, big3, fieldOrder)
	gx1.Add(gx1, curve.Params().B)
	e1 := isSquare(gx1, fieldOrder)
	x2 := new(big.Int).Add(c2, t4)
	gx2 := new(big.Int).Exp(x2, big3, fieldOrder)
	gx2.Add(gx2, curve.Params().B)
	e2 := (isSquare(gx2, fieldOrder) && (!e1))
	x3 := new(big.Int).Exp(t2, big2, fieldOrder)
	x3.Mul(x3, t3)
	x3.Exp(x3, big2, fieldOrder)
	x3.Mul(x3, c4)
	x3.Add(x3, big1)
	x := cmov(x3, x1, e1)
	x = cmov(x, x2, e2)
	x.Mod(x, fieldOrder)
	gx := new(big.Int).Exp(x, big3, fieldOrder)
	gx.Add(gx, curve.Params().B)
	y := new(big.Int).ModSqrt(gx, fieldOrder)
	e3 := u.Bit(0) == y.Bit(0)
	y = cmov(new(big.Int).Neg(y), y, e3)
	y = y.Mod(y, fieldOrder)
	return pt.NewECPoint(curve, x, y)
}
