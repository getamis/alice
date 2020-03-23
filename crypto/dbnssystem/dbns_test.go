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

package dbnssystem

import (
	"math/big"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("DBNS", func() {
	DescribeTable("ExpansionBase2And3()", func(number *big.Int) {
		dbnsMentor := NewDBNS(6)
		expansion, err := dbnsMentor.ExpansionBase2And3(number)
		Expect(err).Should(BeNil())
		got := computeSumFromExpansion(expansion)
		Expect(got.Cmp(number) == 0).Should(BeTrue())
	},
		Entry("Input value:", big.NewInt(20)),
		Entry("Input value:", big.NewInt(841232)),
		Entry("Input value:", big.NewInt(33911)),
		Entry("Input value:", big.NewInt(333242341)),
		Entry("Input value:", big.NewInt(56871)),
	)
})

func TestDBNSsystem(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "DBNSsystem Suite")
}

func computeSumFromExpansion(expansion []*expansion23) *big.Int {
	R := big.NewInt(0)
	T := big.NewInt(1)
	big2 := big.NewInt(2)
	a, b, index := 0, 0, 0
	for index < len(expansion) {
		exp2 := expansion[index].GetExp2()
		for a < exp2 {
			T.Mul(T, big2)
			a++
		}
		exp3 := expansion[index].GetExp3()
		for b < exp3 {
			T.Mul(T, big3)
			b++
		}
		sign := expansion[index].GetSign()
		if sign == 1 {
			R.Add(R, T)
		} else {
			R.Sub(R, T)
		}
		index++
	}
	return R
}
