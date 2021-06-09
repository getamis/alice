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

package binaryfield

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("binary operation test", func() {
	DescribeTable("Add", func(expectedLow uint64, expectedUp uint64) {
		a := NewFieldElement(1, 1)
		b := NewFieldElement(2, 1)
		expected := NewFieldElement(expectedLow, expectedUp)
		got := a.Add(b)
		Expect(got.Equal(expected)).Should(BeTrue())
	},
		Entry("NewFieldElement(1, 1)+ NewFieldElement(2, 1) = NewFieldElement(1, 1)+ NewFieldElement(3, 0)", uint64(3), uint64(0)),
	)
})

func TestBinaryField(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BinaryField Test")
}
