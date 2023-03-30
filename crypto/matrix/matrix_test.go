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
package matrix

import (
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var fieldOrder = big.NewInt(101)
var bigFieldOrder, _ = new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)

var _ = Describe("Matrix test", func() {
	var ma = [][]*big.Int{
		{big.NewInt(1), big.NewInt(3), big.NewInt(2)},
		{big.NewInt(2), big.NewInt(7), big.NewInt(15)},
		{big.NewInt(3), big.NewInt(6), big.NewInt(81)},
	}
	var m *Matrix
	BeforeEach(func() {
		var err error
		m, err = NewMatrix(fieldOrder, ma)
		Expect(err).Should(BeNil())
	})
	Context("NewMatrix()", func() {
		It("should be ok", func() {
			for i, mm := range ma {
				for j, mmm := range mm {
					Expect(m.matrix[i][j]).Should(Equal(mmm))
				}
			}
		})

		It("nil field order", func() {
			m, err := NewMatrix(nil, ma)
			Expect(err).Should(Equal(ErrNonPrimeFieldOrder))
			Expect(m).Should(BeNil())
		})

		It("nil matrix", func() {
			m, err := NewMatrix(fieldOrder, nil)
			Expect(err).Should(Equal(ErrZeroRows))
			Expect(m).Should(BeNil())
		})

		It("zero column", func() {
			m, err := NewMatrix(fieldOrder, [][]*big.Int{
				{},
				{},
			})
			Expect(err).Should(Equal(ErrZeroColumns))
			Expect(m).Should(BeNil())
		})

		It("inconsistent columns", func() {
			m, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(1), big.NewInt(2)},
				{big.NewInt(1)},
			})
			Expect(err).Should(Equal(ErrInconsistentColumns))
			Expect(m).Should(BeNil())
		})

		It("nil item", func() {
			m, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(1), big.NewInt(2)},
				{big.NewInt(1), nil},
			})
			Expect(err).Should(Equal(ErrNilMatrix))
			Expect(m).Should(BeNil())
		})

		It("over size of the number of column or row", func() {
			identity, err := newIdentityMatrix(150, bigFieldOrder)
			Expect(err).Should(BeNil())
			m, err := NewMatrix(fieldOrder, identity.GetMatrix())
			Expect(err).Should(Equal(ErrMaximalSizeOfMatrice))
			Expect(m).Should(BeNil())
		})
	})

	It("Copy()", func() {
		Expect(m.Copy()).Should(Equal(m))
	})

	It("GetMatrix()", func() {
		Expect(m.GetMatrix()).Should(Equal(ma))
	})

	Context("Get()", func() {
		It("should be ok", func() {
			Expect(m.Get(0, 0)).Should(Equal(ma[0][0]))
		})

		It("over the number of rows", func() {
			Expect(m.Get(m.numberRow, 0)).Should(BeNil())
		})

		It("over the number of columns", func() {
			Expect(m.Get(0, m.numberColumn)).Should(BeNil())
		})
	})

	Context("GetColumn()", func() {
		It("should be ok", func() {
			for i := uint64(0); i < m.GetNumberColumn(); i++ {
				got, err := m.GetColumn(i)
				Expect(err).Should(BeNil())

				exp := make([]*big.Int, m.GetNumberRow())
				for j := uint64(0); j < m.GetNumberRow(); j++ {
					exp[j] = ma[j][i]
				}
				Expect(got).Should(Equal(exp))
			}
		})

		It("out of range", func() {
			cs, err := m.GetColumn(m.GetNumberColumn())
			Expect(err).Should(Equal(ErrOutOfRange))
			Expect(cs).Should(BeNil())
		})
	})

	Context("GetRow()", func() {
		It("should be ok", func() {
			for i := uint64(0); i < m.GetNumberRow(); i++ {
				got, err := m.GetRow(i)
				Expect(err).Should(BeNil())
				Expect(got).Should(Equal(ma[i]))
			}
		})

		It("out of range", func() {
			cs, err := m.GetRow(m.GetNumberRow())
			Expect(err).Should(Equal(ErrOutOfRange))
			Expect(cs).Should(BeNil())
		})
	})

	Context("Add()", func() {
		It("should be ok", func() {
			matrixA, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(11), big.NewInt(18), big.NewInt(19)},
				{big.NewInt(45), big.NewInt(74), big.NewInt(81)},
			})
			Expect(err).Should(BeNil())
			matrixB, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(10), big.NewInt(1), big.NewInt(1)},
				{big.NewInt(4), big.NewInt(7), big.NewInt(80)},
			})
			Expect(err).Should(BeNil())

			got, err := matrixA.Add(matrixB)
			Expect(err).Should(BeNil())

			expected, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(21), big.NewInt(19), big.NewInt(20)},
				{big.NewInt(49), big.NewInt(81), big.NewInt(60)},
			})
			Expect(err).Should(BeNil())
			Expect(got).Should(Equal(expected))
		})
	})

	Context("multiply()", func() {
		DescribeTable("should be ok", func(a [][]*big.Int, b [][]*big.Int, expected [][]*big.Int) {
			matrixA, err := NewMatrix(fieldOrder, a)
			Expect(err).Should(BeNil())

			matrixB, err := NewMatrix(fieldOrder, b)
			Expect(err).Should(BeNil())

			got, err := matrixA.multiply(matrixB)
			Expect(err).Should(BeNil())
			Expect(got.GetMatrix()).Should(Equal(expected))
		},
			Entry("square matrix", [][]*big.Int{
				{big.NewInt(1), big.NewInt(2), big.NewInt(5)},
				{big.NewInt(5), big.NewInt(8), big.NewInt(7)},
				{big.NewInt(1), big.NewInt(2), big.NewInt(5)},
			}, [][]*big.Int{
				{big.NewInt(1), big.NewInt(2), big.NewInt(5)},
				{big.NewInt(5), big.NewInt(8), big.NewInt(7)},
				{big.NewInt(1), big.NewInt(2), big.NewInt(5)},
			}, [][]*big.Int{
				{big.NewInt(16), big.NewInt(28), big.NewInt(44)},
				{big.NewInt(52), big.NewInt(88), big.NewInt(15)},
				{big.NewInt(16), big.NewInt(28), big.NewInt(44)},
			}),
			Entry("non-square matrix", [][]*big.Int{
				{big.NewInt(1), big.NewInt(2)},
				{big.NewInt(5), big.NewInt(8)},
				{big.NewInt(3), big.NewInt(0)},
			}, [][]*big.Int{
				{big.NewInt(1), big.NewInt(2), big.NewInt(5)},
				{big.NewInt(5), big.NewInt(8), big.NewInt(7)},
			}, [][]*big.Int{
				{big.NewInt(11), big.NewInt(18), big.NewInt(19)},
				{big.NewInt(45), big.NewInt(74), big.NewInt(81)},
				{big.NewInt(3), big.NewInt(6), big.NewInt(15)},
			}),
		)
	})

	Context("swapRow()", func() {
		It("should be ok", func() {
			mcopy := m.Copy()
			got, err := mcopy.swapRow(0, 1)
			Expect(err).Should(BeNil())
			Expect(got.matrix).Should(Equal([][]*big.Int{
				{big.NewInt(2), big.NewInt(7), big.NewInt(15)},
				{big.NewInt(1), big.NewInt(3), big.NewInt(2)},
				{big.NewInt(3), big.NewInt(6), big.NewInt(81)},
			}))
		})

		It("out of range", func() {
			got, err := m.swapRow(m.GetNumberRow(), 1)
			Expect(err).Should(Equal(ErrOutOfRange))
			Expect(got).Should(BeNil())
		})

		It("same rank", func() {
			got, err := m.swapRow(1, 1)
			Expect(err).Should(BeNil())
			Expect(got).Should(Equal(m))
		})
	})

	Context("swapColumn()", func() {
		It("should be ok", func() {
			mcopy := m.Copy()
			got, err := mcopy.swapColumn(0, 1)
			Expect(err).Should(BeNil())
			Expect(got.matrix).Should(Equal([][]*big.Int{
				{big.NewInt(3), big.NewInt(1), big.NewInt(2)},
				{big.NewInt(7), big.NewInt(2), big.NewInt(15)},
				{big.NewInt(6), big.NewInt(3), big.NewInt(81)},
			}))
		})

		It("out of range", func() {
			got, err := m.swapColumn(m.GetNumberColumn(), 1)
			Expect(err).Should(Equal(ErrOutOfRange))
			Expect(got).Should(BeNil())
		})

		It("same number", func() {
			got, err := m.swapColumn(1, 1)
			Expect(err).Should(BeNil())
			Expect(got).Should(Equal(m))
		})
	})

	Context("Transpose()", func() {
		DescribeTable("should be ok", func(a [][]*big.Int, expected [][]*big.Int) {
			ma, err := NewMatrix(bigFieldOrder, a)
			Expect(err).Should(BeNil())
			Expect(ma.Transpose().GetMatrix()).Should(Equal(expected))
		}, Entry("square matrix", ma, [][]*big.Int{
			{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
			{big.NewInt(3), big.NewInt(7), big.NewInt(6)},
			{big.NewInt(2), big.NewInt(15), big.NewInt(81)},
		}), Entry("non-square matrix", [][]*big.Int{
			{big.NewInt(1), big.NewInt(2)},
			{big.NewInt(5), big.NewInt(8)},
			{big.NewInt(3), big.NewInt(0)},
		}, [][]*big.Int{
			{big.NewInt(1), big.NewInt(5), big.NewInt(3)},
			{big.NewInt(2), big.NewInt(8), big.NewInt(0)},
		}))
	})

	DescribeTable("getNonZeroCoefficientByRow()", func(index uint64, expGot uint64, expFound bool) {
		m, err := NewMatrix(fieldOrder, [][]*big.Int{
			{big.NewInt(0), big.NewInt(18), big.NewInt(19)},
			{big.NewInt(45), big.NewInt(0), big.NewInt(81)},
			{big.NewInt(3), big.NewInt(0), big.NewInt(15)},
		})
		Expect(err).Should(BeNil())
		Expect(m).ShouldNot(BeNil())

		got, found := m.getNonZeroCoefficientByRow(index, index)
		Expect(got).Should(Equal(expGot))
		Expect(found).Should(Equal(expFound))
	},
		Entry("normal case", uint64(0), uint64(1), true),
		Entry("out of rank", uint64(3), uint64(0), false),
		Entry("not found", uint64(1), uint64(0), false),
	)

	Context("GetGaussElimination()", func() {
		It("should be ok", func() {
			gotUpper, gotLower, _, err := m.getGaussElimination()
			Expect(err).Should(BeNil())

			// Check upper matrix
			expectedUpper, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(1), big.NewInt(3), big.NewInt(2)},
				{big.NewInt(0), big.NewInt(1), big.NewInt(11)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(108)},
			})
			Expect(err).Should(BeNil())
			Expect(gotUpper.modulus().Equal(expectedUpper)).Should(BeTrue())

			// Check lower matrix
			expectLower, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(1), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(-2), big.NewInt(1), big.NewInt(0)},
				{big.NewInt(-9), big.NewInt(3), big.NewInt(1)},
			})
			Expect(err).Should(BeNil())
			Expect(gotLower.modulus().Equal(expectLower)).Should(BeTrue())
		})
	})

	Context("Inverse()", func() {
		It("should be ok", func() {
			got, err := m.Inverse()
			Expect(err).Should(BeNil())
			Expect(got.GetMatrix()).Should(Equal([][]*big.Int{
				{big.NewInt(97), big.NewInt(68), big.NewInt(91)},
				{big.NewInt(41), big.NewInt(54), big.NewInt(85)},
				{big.NewInt(42), big.NewInt(87), big.NewInt(29)},
			}))
		})

		DescribeTable("should be ok for big number", func(a [][]*big.Int, expectedIntStrs [][]string) {
			m, err := NewMatrix(bigFieldOrder, a)
			Expect(err).Should(BeNil())
			Expect(m).ShouldNot(BeNil())

			got, err := m.Inverse()
			Expect(err).Should(BeNil())

			expected := make([][]*big.Int, len(expectedIntStrs))
			for i := 0; i < len(expectedIntStrs); i++ {
				expected[i] = make([]*big.Int, len(expectedIntStrs[i]))
				for j := 0; j < len(expectedIntStrs[i]); j++ {
					expected[i][j], _ = new(big.Int).SetString(expectedIntStrs[i][j], 10)
				}
			}
			Expect(got.matrix).Should(Equal(expected))
		}, Entry("case 1", ma, [][]string{
			{
				"67545385388434447330416407921734612914155245829460360889853011832552260871701",
				"93276960774504712980098849034776370214785815669254784085987492530667407870436",
				"31092320258168237660032949678258790071595271889751594695329164176889135956813",
			},
			{
				"9649340769776349618630915417390658987736463689922908698550430261793180124527",
				"112575642314057412217360679869557688190258743049100601483088353054253768119495",
				"37525214104685804072453559956519229396752914349700200494362784351417922706498",
			},
			{
				"9649340769776349618630915417390658987736463689922908698550430261793180124528",
				"73978279234952013742837018199995052239312888289408966688886632007081047621382",
				"101854152569861468196659662739123622648329338949186258484698986096705790203352",
			},
		}),
			Entry("case 2", [][]*big.Int{
				{big.NewInt(4), big.NewInt(10), big.NewInt(30)},
				{big.NewInt(10), big.NewInt(30), big.NewInt(100)},
				{big.NewInt(30), big.NewInt(100), big.NewInt(354)},
			}, [][]string{
				{
					"28948022309329048855892746252171976963209391069768726095651290785379540373592",
					"86844066927987146567678238756515930889628173209306178286953872356138621120746",
					"86844066927987146567678238756515930889628173209306178286953872356138621120754",
				},
				{
					"86844066927987146567678238756515930889628173209306178286953872356138621120746",
					"17368813385597429313535647751303186177925634641861235657390774471227724224157",
					"28948022309329048855892746252171976963209391069768726095651290785379540373583",
				},
				{
					"86844066927987146567678238756515930889628173209306178286953872356138621120754",
					"28948022309329048855892746252171976963209391069768726095651290785379540373583",
					"86844066927987146567678238756515930889628173209306178286953872356138621120753",
				},
			}),
		)

		It("non-exist", func() {
			m, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(0), big.NewInt(3), big.NewInt(2)},
				{big.NewInt(0), big.NewInt(7), big.NewInt(15)},
				{big.NewInt(0), big.NewInt(6), big.NewInt(81)},
			})
			Expect(err).Should(BeNil())
			Expect(m).ShouldNot(BeNil())
			got, err := m.Inverse()
			Expect(err).Should(Equal(ErrNotInvertableMatrix))
			Expect(got).Should(BeNil())
		})
	})

	Context("multiInverseDiagonal()", func() {
		It("should be ok", func() {
			m, err := NewMatrix(bigFieldOrder, [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(5)},
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			})
			Expect(err).Should(BeNil())
			Expect(m).ShouldNot(BeNil())

			diagonalMatrice, _ := NewMatrix(bigFieldOrder, [][]*big.Int{
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(14)},
			})

			got, err := m.multiInverseDiagonal(diagonalMatrice)
			Expect(err).Should(BeNil())

			inverse11 := new(big.Int).ModInverse(big.NewInt(2), bigFieldOrder)
			inverse22 := new(big.Int).ModInverse(big.NewInt(3), bigFieldOrder)
			inverse33 := new(big.Int).ModInverse(big.NewInt(-1), bigFieldOrder)
			inverse44 := new(big.Int).ModInverse(big.NewInt(14), bigFieldOrder)

			original, err := NewMatrix(bigFieldOrder, [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(5)},
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			})
			Expect(err).Should(BeNil())

			inverseDiagonal, err := NewMatrix(bigFieldOrder, [][]*big.Int{
				{inverse11, big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), inverse22, big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), inverse33, big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), inverse44},
			})
			Expect(err).Should(BeNil())

			expected, err := inverseDiagonal.multiply(original)
			Expect(err).Should(BeNil())
			Expect(got.Equal(expected)).Should(BeTrue())
		})
	})

	Context("modInverse()", func() {
		It("should be ok", func() {
			m, err := NewMatrix(bigFieldOrder, [][]*big.Int{
				{big.NewInt(0), big.NewInt(1), big.NewInt(4)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(5)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(2)},
			})
			Expect(err).Should(BeNil())
			Expect(m).ShouldNot(BeNil())
			got := m.modInverse(1, 2)
			expected := new(big.Int).ModInverse(big.NewInt(5), bigFieldOrder)
			Expect(got.Cmp(expected)).Should(BeZero())
		})
	})

	Context("Determinant()", func() {
		DescribeTable("should be ok", func(a [][]*big.Int, expectedStr string) {
			m, err := NewMatrix(bigFieldOrder, a)
			Expect(err).Should(BeNil())
			got, err := m.Determinant()
			expected, _ := new(big.Int).SetString(expectedStr, 10)
			Expect(got).Should(Equal(expected))
			Expect(err).Should(BeNil())
		}, Entry("case 1", [][]*big.Int{
			{big.NewInt(0), big.NewInt(3), big.NewInt(2)},
			{big.NewInt(0), big.NewInt(3), big.NewInt(2)},
			{big.NewInt(0), big.NewInt(6), big.NewInt(81)},
		}, "0"),
			Entry("case 2", [][]*big.Int{
				{big.NewInt(1), big.NewInt(3), big.NewInt(2)},
				{big.NewInt(2), big.NewInt(7), big.NewInt(15)},
				{big.NewInt(3), big.NewInt(6), big.NewInt(81)},
			}, "108"),
			Entry("case 3", [][]*big.Int{
				{big.NewInt(1), big.NewInt(1), big.NewInt(2)},
				{big.NewInt(2), big.NewInt(2), big.NewInt(15)},
				{big.NewInt(3), big.NewInt(3), big.NewInt(81)},
			}, "0"),
			Entry("case 4", [][]*big.Int{
				{big.NewInt(1), big.NewInt(1), big.NewInt(2)},
				{big.NewInt(2), big.NewInt(2), big.NewInt(0)},
				{big.NewInt(3), big.NewInt(0), big.NewInt(81)},
			}, "115792089237316195423570985008687907852837564279074904382605163141518161494325"),
			Entry("case 5", [][]*big.Int{
				{big.NewInt(1), big.NewInt(1), big.NewInt(2), big.NewInt(2)},
				{big.NewInt(0), big.NewInt(2), big.NewInt(0), big.NewInt(-2)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(2), big.NewInt(-5)},
				{big.NewInt(0), big.NewInt(-99), big.NewInt(14), big.NewInt(0)},
			}, "115792089237316195423570985008687907852837564279074904382605163141518161494081"),
			Entry("case 6", [][]*big.Int{
				{big.NewInt(1), big.NewInt(0), big.NewInt(2), big.NewInt(2)},
				{big.NewInt(0), big.NewInt(2), big.NewInt(0), big.NewInt(-2)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(2), big.NewInt(-5)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			}, "0"),
		)
	})

	Context("GetMatrixRank()", func() {
		DescribeTable("should be ok", func(a [][]*big.Int, expected uint64) {
			m, err := NewMatrix(bigFieldOrder, a)
			Expect(err).Should(BeNil())
			got, err := m.GetMatrixRank(bigFieldOrder)
			Expect(got).Should(Equal(expected))
			Expect(err).Should(BeNil())
		},
			Entry("Rank 0 #0", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			}, uint64(0)),

			Entry("Rank 1 #0", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(2), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			}, uint64(1)),
			Entry("Rank 1 #1", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(2), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(4), big.NewInt(2)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(6), big.NewInt(3)},
			}, uint64(1)),

			Entry("Rank 1 #2", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(-2), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-4), big.NewInt(2)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-6), big.NewInt(3)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-6), big.NewInt(3)},
			}, uint64(1)),

			Entry("Rank 1 #3", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}, uint64(1)),

			Entry("Rank 2 #0", [][]*big.Int{
				{big.NewInt(1), big.NewInt(1), big.NewInt(2)},
				{big.NewInt(2), big.NewInt(2), big.NewInt(15)},
				{big.NewInt(3), big.NewInt(3), big.NewInt(81)},
			}, uint64(2)),
			Entry("Rank 2 #1", [][]*big.Int{
				{big.NewInt(1), big.NewInt(0), big.NewInt(2), big.NewInt(1)},
				{big.NewInt(2), big.NewInt(0), big.NewInt(15), big.NewInt(2)},
				{big.NewInt(3), big.NewInt(0), big.NewInt(81), big.NewInt(3)},
			}, uint64(2)),
			Entry("Rank 2 #2", [][]*big.Int{
				{big.NewInt(2), big.NewInt(1), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			}, uint64(2)),
			Entry("Rank 2 #3", [][]*big.Int{
				{big.NewInt(0), big.NewInt(1), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(1)},
			}, uint64(2)),

			Entry("Rank 3 #0", [][]*big.Int{
				{big.NewInt(1), big.NewInt(1), big.NewInt(2)},
				{big.NewInt(2), big.NewInt(3), big.NewInt(15)},
				{big.NewInt(3), big.NewInt(3), big.NewInt(81)},
				{big.NewInt(1), big.NewInt(1), big.NewInt(5)},
			}, uint64(3)),
			Entry("Rank 3 #1", [][]*big.Int{
				{big.NewInt(1), big.NewInt(1), big.NewInt(2), big.NewInt(1)},
				{big.NewInt(2), big.NewInt(3), big.NewInt(15), big.NewInt(2)},
				{big.NewInt(3), big.NewInt(3), big.NewInt(81), big.NewInt(3)},
			}, uint64(3)),
		)
	})

	Context("DeleteRow()", func() {
		DescribeTable("should be ok", func(a [][]*big.Int, from uint64, to uint64, expectedM [][]*big.Int) {
			m, err := NewMatrix(bigFieldOrder, a)
			Expect(err).Should(BeNil())
			got, err := m.DeleteRow(from, to)
			Expect(err).Should(BeNil())

			expected, err := NewMatrix(bigFieldOrder, expectedM)
			Expect(err).Should(BeNil())
			Expect(got).Should(Equal(expected))
		},
			Entry("#0", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}, uint64(1), uint64(2), [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}),
			Entry("#1", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}, uint64(1), uint64(1), [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}),
			Entry("#2", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}, uint64(0), uint64(0), [][]*big.Int{
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}),
		)

		It("out of the number of rows", func() {
			got, err := m.DeleteRow(0, m.numberRow)
			Expect(err).Should(Equal(ErrOutOfRange))
			Expect(got).Should(BeNil())
		})

		It("from is larger than to", func() {
			got, err := m.DeleteRow(1, 0)
			Expect(err).Should(Equal(ErrOutOfRange))
			Expect(got).Should(BeNil())
		})
	})

	Context("DeleteColumn()", func() {
		DescribeTable("should be ok", func(a [][]*big.Int, from uint64, to uint64, expectedM [][]*big.Int) {
			m, err := NewMatrix(bigFieldOrder, a)
			Expect(err).Should(BeNil())
			got, err := m.DeleteColumn(from, to)
			Expect(err).Should(BeNil())

			expected, err := NewMatrix(bigFieldOrder, expectedM)
			Expect(err).Should(BeNil())
			Expect(got).Should(Equal(expected))
		},
			Entry("#0", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}, uint64(1), uint64(2), [][]*big.Int{
				{big.NewInt(0), big.NewInt(0)},
				{big.NewInt(2), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0)},
			}),
			Entry("#1", [][]*big.Int{
				{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(0)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(-1), big.NewInt(0)},
			}, uint64(1), uint64(3), [][]*big.Int{
				{big.NewInt(0)},
				{big.NewInt(2)},
				{big.NewInt(0)},
				{big.NewInt(0)},
			}),
		)

	})

	Context("Pseudoinverse()", func() {
		DescribeTable("should be ok", func(a [][]*big.Int, expectedIntStrs [][]string) {
			m, err := NewMatrix(bigFieldOrder, a)
			Expect(err).Should(BeNil())

			got, err := m.Pseudoinverse()
			Expect(err).Should(BeNil())

			expectedInts := make([][]*big.Int, len(expectedIntStrs))
			for i := 0; i < len(expectedIntStrs); i++ {
				expectedInts[i] = make([]*big.Int, len(expectedIntStrs[i]))
				for j := 0; j < len(expectedIntStrs[i]); j++ {
					expectedInts[i][j], _ = new(big.Int).SetString(expectedIntStrs[i][j], 10)
				}
			}

			expected, err := NewMatrix(bigFieldOrder, expectedInts)
			Expect(err).Should(BeNil())
			Expect(got.GetMatrix()).Should(Equal(expected.GetMatrix()))
		},
			Entry("#0", [][]*big.Int{
				{big.NewInt(1), big.NewInt(1), big.NewInt(1)},
				{big.NewInt(0), big.NewInt(1), big.NewInt(4)},
				{big.NewInt(0), big.NewInt(1), big.NewInt(6)},
				{big.NewInt(0), big.NewInt(0), big.NewInt(2)},
			}, [][]string{
				{
					"1",
					"19298681539552699237261830834781317975472927379845817397100860523586360249055",
					"96493407697763496186309154173906589877364636899229086985504302617931801245281",
					"77194726158210796949047323339125271901891709519383269588403442094345440996226",
				},
				{
					"0",
					"77194726158210796949047323339125271901891709519383269588403442094345440996226",
					"38597363079105398474523661669562635950945854759691634794201721047172720498112",
					"77194726158210796949047323339125271901891709519383269588403442094345440996223",
				},
				{
					"0",
					"19298681539552699237261830834781317975472927379845817397100860523586360249056",
					"96493407697763496186309154173906589877364636899229086985504302617931801245281",
					"77194726158210796949047323339125271901891709519383269588403442094345440996225",
				},
			}),
			Entry("#1", [][]*big.Int{
				{big.NewInt(4), big.NewInt(10), big.NewInt(30)},
				{big.NewInt(10), big.NewInt(30), big.NewInt(100)},
				{big.NewInt(30), big.NewInt(100), big.NewInt(354)},
			}, [][]string{
				{
					"28948022309329048855892746252171976963209391069768726095651290785379540373592",
					"86844066927987146567678238756515930889628173209306178286953872356138621120746",
					"86844066927987146567678238756515930889628173209306178286953872356138621120754",
				},
				{
					"86844066927987146567678238756515930889628173209306178286953872356138621120746",
					"17368813385597429313535647751303186177925634641861235657390774471227724224157",
					"28948022309329048855892746252171976963209391069768726095651290785379540373583",
				},
				{
					"86844066927987146567678238756515930889628173209306178286953872356138621120754",
					"28948022309329048855892746252171976963209391069768726095651290785379540373583",
					"86844066927987146567678238756515930889628173209306178286953872356138621120753",
				},
			}),
		)

		It("not invertable", func() {
			m, err := NewMatrix(bigFieldOrder, [][]*big.Int{
				{big.NewInt(0), big.NewInt(3), big.NewInt(2)},
				{big.NewInt(0), big.NewInt(7), big.NewInt(15)},
				{big.NewInt(0), big.NewInt(6), big.NewInt(81)},
			})
			Expect(err).Should(BeNil())

			got, err := m.Pseudoinverse()
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ErrNotInvertableMatrix))
		})
	})

	It("Not square matrix", func() {
		m, err := NewMatrix(bigFieldOrder, [][]*big.Int{
			{big.NewInt(0), big.NewInt(7), big.NewInt(15)},
			{big.NewInt(0), big.NewInt(6), big.NewInt(81)},
		})
		Expect(err).Should(BeNil())

		_, _, _, err = m.getGaussElimination()
		Expect(err).Should(Equal(ErrNotSquareMatrix))

		_, err = m.Determinant()
		Expect(err).Should(Equal(ErrNotSquareMatrix))
	})

	Context("Equal()", func() {
		It("should be ok", func() {
			Expect(m.Equal(m)).Should(BeTrue())
		})

		It("should be ok, different instances", func() {
			m2, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(1), big.NewInt(3), big.NewInt(2)},
				{big.NewInt(2), big.NewInt(7), big.NewInt(15)},
				{big.NewInt(3), big.NewInt(6), big.NewInt(81)},
			})
			Expect(err).Should(BeNil())
			Expect(m.Equal(m2)).Should(BeTrue())
		})

		It("different row numbers", func() {
			m2, err := NewMatrix(bigFieldOrder, [][]*big.Int{
				{big.NewInt(0), big.NewInt(7), big.NewInt(15)},
				{big.NewInt(0), big.NewInt(6), big.NewInt(81)},
			})
			Expect(err).Should(BeNil())
			Expect(m.Equal(m2)).Should(BeFalse())
		})

		It("different column numbers", func() {
			m2, err := NewMatrix(bigFieldOrder, [][]*big.Int{
				{big.NewInt(0), big.NewInt(7)},
				{big.NewInt(0), big.NewInt(6)},
				{big.NewInt(0), big.NewInt(7)},
			})
			Expect(err).Should(BeNil())
			Expect(m.Equal(m2)).Should(BeFalse())
		})

		It("different the order of fields", func() {
			m2, err := NewMatrix(bigFieldOrder, [][]*big.Int{
				{big.NewInt(1), big.NewInt(3), big.NewInt(2)},
				{big.NewInt(2), big.NewInt(7), big.NewInt(15)},
				{big.NewInt(3), big.NewInt(6), big.NewInt(81)},
			})
			Expect(err).Should(BeNil())
			Expect(m.Equal(m2)).Should(BeFalse())
		})

		It("different items", func() {
			m2, err := NewMatrix(fieldOrder, [][]*big.Int{
				{big.NewInt(1), big.NewInt(3), big.NewInt(2)},
				{big.NewInt(2), big.NewInt(7), big.NewInt(15)},
				{big.NewInt(3), big.NewInt(6), big.NewInt(82)},
			})
			Expect(err).Should(BeNil())
			Expect(m.Equal(m2)).Should(BeFalse())
		})
	})
})
