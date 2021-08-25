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
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/edwards/v2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestEllipticcurve(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ellipticcurve Suite")
}

var (
	curveList = []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), btcec.S256(), edwards.Edwards()}
)

var _ = Describe("Elliptic curves", func() {
	Context("ScalarBaseMult()", func() {
		It("Verify 0*G is x = nil, y = nil(i.e. the identity element)", func() {
			for i := 0; i < len(curveList); i++ {
				result := ScalarBaseMult(curveList[i], big.NewInt(0))
				Expect(result.x).To(BeNil())
				Expect(result.y).To(BeNil())
			}
		})
	})

	Context("ComputeLinearCombinationPoint()", func() {
		It("Verify 2*G + (-3)*G + G + 0*G + 2*G = 2*G", func() {
			for i := 0; i < len(curveList); i++ {
				pointList := make([]*ECPoint, 5)
				pointList[0] = ScalarBaseMult(curveList[i], big.NewInt(1))
				pointList[1] = ScalarBaseMult(curveList[i], big.NewInt(1))
				pointList[2] = ScalarBaseMult(curveList[i], big.NewInt(1))
				pointList[3] = ScalarBaseMult(curveList[i], big.NewInt(1))
				pointList[4] = ScalarBaseMult(curveList[i], big.NewInt(1))
				scalarList := make([]*big.Int, 5)
				scalarList[0] = big.NewInt(2)
				scalarList[1] = big.NewInt(-3)
				scalarList[2] = big.NewInt(1)
				scalarList[3] = big.NewInt(0)
				scalarList[4] = big.NewInt(2)
				result, err := ComputeLinearCombinationPoint(scalarList, pointList)
				Expect(err).To(BeNil())

				expected := ScalarBaseMult(curveList[i], big.NewInt(2))
				Expect(result).To(Equal(expected))
			}
		})

		It("Verify failure case: different length", func() {
			pointList := make([]*ECPoint, 3)
			scalarList := make([]*big.Int, 4)
			p, err := ComputeLinearCombinationPoint(scalarList, pointList)
			Expect(err).To(Equal(ErrDifferentLength))
			Expect(p).To(BeNil())
		})

		It("Verify failure case: empty slice", func() {
			pointList := make([]*ECPoint, 3)
			scalarList := make([]*big.Int, 0)
			p, err := ComputeLinearCombinationPoint(scalarList, pointList)
			Expect(err).To(Equal(ErrEmptySlice))
			Expect(p).To(BeNil())
		})

		It("Verify failure case: Failed to add points", func() {
			pointList := make([]*ECPoint, 5)
			pointList[0] = ScalarBaseMult(curveList[0], big.NewInt(1))
			pointList[1] = ScalarBaseMult(curveList[0], big.NewInt(1))
			pointList[2] = ScalarBaseMult(curveList[0], big.NewInt(1))
			pointList[3] = ScalarBaseMult(curveList[0], big.NewInt(1))
			pointList[4] = ScalarBaseMult(curveList[1], big.NewInt(1)) // different curve
			scalarList := make([]*big.Int, 5)
			scalarList[0] = big.NewInt(2)
			scalarList[1] = big.NewInt(-3)
			scalarList[2] = big.NewInt(1)
			scalarList[3] = big.NewInt(0)
			scalarList[4] = big.NewInt(2)
			result, err := ComputeLinearCombinationPoint(scalarList, pointList)
			Expect(err).To(Equal(ErrDifferentCurve))
			Expect(result).To(BeNil())
		})
	})
})
