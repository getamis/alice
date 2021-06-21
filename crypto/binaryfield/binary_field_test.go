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

	It("copy()", func() {
		a := NewFieldElement(6, 1)
		got := a.Copy()
		Expect(got).Should(Equal(a))
	})

	It("GetLow()", func() {
		a := NewFieldElement(6, 1)
		got := a.GetLow()
		Expect(got).Should(BeNumerically("==", 6))
	})

	It("GetHigh()", func() {
		a := NewFieldElement(6, 1)
		got := a.GetHigh()
		Expect(got).Should(BeNumerically("==", 1))
	})

	Context("ScalMulFieldElement()", func() {
		It("It is OK", func() {
			a := NewFieldElement(6, 1)
			constant := []byte{1, 0}
			got := ScalMulFieldElement(a, constant)
			expected := []*FieldElement{a, NewFieldElement(0, 0)}
			Expect(got).Should(Equal(expected))
		})
	})

	Context("AddVector()", func() {
		It("It is OK", func() {
			a := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(2, 1)}
			b := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(1, 1)}
			got, err := AddVector(a, b)
			Expect(err).Should(BeNil())
			expcted := []*FieldElement{NewFieldElement(0, 0), NewFieldElement(3, 0)}
			Expect(got).Should(Equal(expcted))
		})

		It("not equal length", func() {
			a := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(2, 1)}
			b := []*FieldElement{NewFieldElement(1, 1)}
			_, err := AddVector(a, b)
			Expect(err).Should(Equal(ErrWrongInput))
		})
	})

	It("TransFieldElementMsg and ToFieldElement", func() {
		a := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(2, 1)}
		msg := TransFieldElementMsg(a)
		got := ToFieldElement(msg)
		Expect(got).Should(Equal(a))
	})

	Context("EqualSlice()", func() {
		It("It is OK", func() {
			a := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(2, 1)}
			b := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(2, 1)}
			Expect(EqualSlice(a, b)).Should(BeTrue())
		})
		It("not the same", func() {
			a := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(2, 1)}
			b := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(1, 1)}
			Expect(EqualSlice(a, b)).Should(BeFalse())
		})

		It("not equal length", func() {
			a := []*FieldElement{NewFieldElement(6, 1), NewFieldElement(2, 1)}
			b := []*FieldElement{NewFieldElement(1, 1)}
			Expect(EqualSlice(a, b)).Should(BeFalse())
		})
	})
})

func TestBinaryField(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BinaryField Test")
}
