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
package liss

import (
	"math/big"

	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/matrix"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("group configs test", func() {
	var (
		secp256k1N, _  = new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)
		clParameter, _ = cl.NewCLBaseParameter(big.NewInt(1024), 40, secp256k1N, 1348, 40)
	)
	DescribeTable("generateMatrix()", func(threshold int, totalParticipant int, exptected [][]*big.Int) {
		var groups GroupConfigs = make([]*GroupConfig, 2)
		var err error
		groups[0], err = NewGroup(totalParticipant, threshold)
		Expect(err).Should(BeNil())
		groups[1], err = NewGroup(totalParticipant, threshold)
		Expect(err).Should(BeNil())
		got, err := groups.generateMatrix()
		Expect(err).Should(BeNil())
		e, err := matrix.NewMatrix(nil, exptected)
		Expect(got).Should(Equal(e.ToCSR()))
		Expect(err).Should(BeNil())
	},
		Entry("normal case", 2, 2, [][]*big.Int{
			{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(1)},
			{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
		}),
	)

	DescribeTable("GenerateShares()", func(threshold int, totalParticipant int) {
		var groups GroupConfigs = make([]*GroupConfig, 2)
		var err error
		groups[0], err = NewGroup(totalParticipant, threshold)
		Expect(err).Should(BeNil())
		groups[1], err = NewGroup(totalParticipant, threshold)
		Expect(err).Should(BeNil())
		randomValueMatrix, organizationMatrix, err := groups.GenerateRandomValue(2, 3)
		Expect(err).Should(BeNil())
		_, _, err = groups.GenerateShares(clParameter.GetG(), randomValueMatrix, organizationMatrix)
		Expect(err).Should(BeNil())
	},
		Entry("normal case", 2, 3),
	)
})
