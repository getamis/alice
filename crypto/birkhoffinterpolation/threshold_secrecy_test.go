// Copyright © 2020 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package birkhoffinterpolation

import (
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CheckThresholdSecrecy()", func() {
	var (
		bigNumber   = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
		bigPrime, _ = new(big.Int).SetString(bigNumber, 10)
	)

	bk := func(x int64, rank uint32) *BkParameter {
		return NewBkParameter(big.NewInt(x), rank)
	}

	Describe("ValidateThresholdScheme()", func() {
		It("rejects recoverable shares that disclose the secret below threshold", func() {
			ps := BkParameters{bk(2, 0), bk(1, 1), bk(3, 0)}
			Expect(ps.ValidateThresholdScheme(3, bigPrime)).Should(Equal(ErrBelowThresholdRecovery))
		})

		It("accepts a recoverable threshold-secure sharing", func() {
			ps := BkParameters{bk(1, 0), bk(2, 0), bk(3, 0), bk(4, 0), bk(5, 0)}
			Expect(ps.ValidateThresholdScheme(3, bigPrime)).Should(BeNil())
		})
	})

	It("rejects the threshold-3 pair (2u, 0), (u, 1) that checkRecoverable accepts", func() {
		// f(2u) - 2u*f'(u) = a0 for every quadratic f, so these two shares are the
		// secret; the third bk only supplies the full-rank triple checkRecoverable asks for.
		ps := BkParameters{bk(2, 0), bk(1, 1), bk(3, 0)}
		Expect(ps.checkRecoverable(3, bigPrime)).Should(BeNil())
		Expect(ps.CheckThresholdSecrecy(3, bigPrime)).Should(Equal(ErrBelowThresholdRecovery))
	})

	It("rejects the general construction at threshold 4", func() {
		// t-2 rank-0 shares at x_j and one rank-1 share at u with (z*P(z))'(u) = 0,
		// P(z) = prod (z - x_j): the last coordinate is u + (1/u + sum 1/(u-x_j))^-1.
		u := big.NewInt(2)
		x1 := big.NewInt(1)
		inv := func(v *big.Int) *big.Int { return new(big.Int).ModInverse(v, bigPrime) }
		sum := new(big.Int).Add(inv(u), inv(new(big.Int).Sub(u, x1)))
		sum.Mod(sum, bigPrime)
		x2 := new(big.Int).Add(u, inv(sum))
		x2.Mod(x2, bigPrime)
		ps := BkParameters{
			NewBkParameter(x1, 0),
			NewBkParameter(x2, 0),
			NewBkParameter(u, 1),
			bk(5, 0),
			bk(7, 0),
		}
		Expect(ps.checkRecoverable(4, bigPrime)).Should(BeNil())
		Expect(ps.CheckThresholdSecrecy(4, bigPrime)).Should(Equal(ErrBelowThresholdRecovery))
	})

	It("accepts a plain Shamir sharing", func() {
		ps := BkParameters{bk(1, 0), bk(2, 0), bk(3, 0), bk(4, 0), bk(5, 0)}
		Expect(ps.CheckThresholdSecrecy(3, bigPrime)).Should(BeNil())
	})

	It("accepts a veto layout of ranks 0 and 2 at distinct coordinates", func() {
		ps := BkParameters{bk(1, 0), bk(2, 0), bk(3, 0), bk(4, 2), bk(5, 2), bk(6, 2)}
		Expect(ps.checkRecoverable(4, bigPrime)).Should(BeNil())
		Expect(ps.CheckThresholdSecrecy(4, bigPrime)).Should(BeNil())
	})

	It("accepts mixed ranks at unrelated coordinates", func() {
		ps := BkParameters{bk(1, 0), bk(3, 0), bk(5, 1), bk(7, 1), bk(11, 1)}
		Expect(ps.checkRecoverable(3, bigPrime)).Should(BeNil())
		Expect(ps.CheckThresholdSecrecy(3, bigPrime)).Should(BeNil())
	})

	It("rejects recovery by fewer than threshold minus one shares", func() {
		ps := BkParameters{bk(2, 0), bk(1, 1), bk(3, 0), bk(4, 0)}
		Expect(ps.checkRecoverable(4, bigPrime)).Should(BeNil())
		// A share at zero directly reveals the constant term.
		ps[0] = bk(0, 0)
		Expect(ps.CheckThresholdSecrecy(4, bigPrime)).Should(Equal(ErrBelowThresholdRecovery))
	})

	It("accepts the derivative pair once u is not tied to 2u", func() {
		// Same ranks as the rejected pair, coordinates without the relation.
		ps := BkParameters{bk(5, 0), bk(1, 1), bk(3, 0)}
		Expect(ps.CheckThresholdSecrecy(3, bigPrime)).Should(BeNil())
	})

	It("accepts a rank-deficient coalition whose span excludes the secret", func() {
		// Both derivatives are the same linear functional; neither reveals a0.
		ps := BkParameters{bk(1, 2), bk(2, 2), bk(3, 0), bk(4, 0)}
		Expect(ps.checkRecoverable(3, bigPrime)).Should(BeNil())
		Expect(ps.CheckThresholdSecrecy(3, bigPrime)).Should(BeNil())
	})

	It("has nothing to protect at threshold 1", func() {
		ps := BkParameters{bk(1, 0), bk(2, 0)}
		Expect(ps.CheckThresholdSecrecy(1, bigPrime)).Should(BeNil())
	})

	It("needs at least threshold bks", func() {
		ps := BkParameters{bk(1, 0), bk(2, 0)}
		Expect(ps.CheckThresholdSecrecy(3, bigPrime)).Should(Equal(ErrEqualOrLargerThreshold))
	})
})
