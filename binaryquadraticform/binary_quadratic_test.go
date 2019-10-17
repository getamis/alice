// Copyright © 2019 AMIS Technologies
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

package binaryquadraticform

import (
	"math/big"
	"testing"
)

// Compute the reduced form of a given binary quadratic form.
func TestIsReducedForm(t *testing.T) {

	testbqForm, _ := NewBQuadraticForm(big.NewInt(33), big.NewInt(11), big.NewInt(5))

	got := testbqForm.IsReducedForm()

	if got == true {
		t.Error("Unexpected Result", "got", got, "expected", "False")
	}
}

func TestNegativeDiscriminant1(t *testing.T) {

	_, err := NewBQuadraticForm(big.NewInt(0), big.NewInt(0), big.NewInt(5))

	if err == nil {
		t.Error("Unexpected Result", "err", err, "expected", "nil")
	}
}

func TestNegativeDiscriminant2(t *testing.T) {

	_, err := NewBQuadraticForm(big.NewInt(1), big.NewInt(10), big.NewInt(10))

	if err == nil {
		t.Error("Unexpected Result", "err", err, "expected", "nil")
	}
}

func TestReducedForm1(t *testing.T) {

	got, _ := NewBQuadraticForm(big.NewInt(33), big.NewInt(11), big.NewInt(5))
	got.Reduction()

	if got.a.Cmp(big.NewInt(5)) != 0 || got.b.Cmp(big.NewInt(-1)) != 0 || got.c.Cmp(big.NewInt(27)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=5, b=-1, c=27")
	}
}

func TestReducedForm2(t *testing.T) {
	got, _ := NewBQuadraticForm(big.NewInt(15), big.NewInt(0), big.NewInt(15))

	got.Reduction()

	if got.a.Cmp(big.NewInt(15)) != 0 || got.b.Cmp(big.NewInt(0)) != 0 || got.c.Cmp(big.NewInt(15)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=15, b=0, c=15")
	}
}

func TestReducedForm3(t *testing.T) {
	got, _ := NewBQuadraticForm(big.NewInt(6), big.NewInt(3), big.NewInt(1))

	got.Reduction()

	if got.a.Cmp(big.NewInt(1)) != 0 || got.b.Cmp(big.NewInt(1)) != 0 || got.c.Cmp(big.NewInt(4)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=1, b=1, c=4")
	}
}

func TestReducedForm4(t *testing.T) {

	got, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(0), big.NewInt(3))
	got.Reduction()

	if got.a.Cmp(big.NewInt(1)) != 0 || got.b.Cmp(big.NewInt(0)) != 0 || got.c.Cmp(big.NewInt(3)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=1, b=0, c=3")
	}
}

func TestReducedForm5(t *testing.T) {
	got, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(2), big.NewInt(3))

	got.Reduction()

	if got.a.Cmp(big.NewInt(1)) != 0 || got.b.Cmp(big.NewInt(0)) != 0 || got.c.Cmp(big.NewInt(2)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=1, b=0, c=2")
	}
}

func TestReducedForm6(t *testing.T) {
	got, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(2), big.NewInt(30))

	got.Reduction()

	if got.a.Cmp(big.NewInt(1)) != 0 || got.b.Cmp(big.NewInt(0)) != 0 || got.c.Cmp(big.NewInt(29)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=1, b=0, c=29")
	}
}

func TestReducedForm7(t *testing.T) {
	got, _ := NewBQuadraticForm(big.NewInt(4), big.NewInt(5), big.NewInt(3))

	got.Reduction()

	if got.a.Cmp(big.NewInt(2)) != 0 || got.b.Cmp(big.NewInt(-1)) != 0 || got.c.Cmp(big.NewInt(3)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=2, b=-1, c=3")
	}
}

// Compute the reduced composition of two quadratic forms
func TestComposition1(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(1), big.NewInt(6))
	form2, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(1), big.NewInt(6))

	Droot4th := big.NewInt(2)
	got := form1.Composition(form2, Droot4th)

	if got.a.Cmp(big.NewInt(1)) != 0 || got.b.Cmp(big.NewInt(1)) != 0 || got.c.Cmp(big.NewInt(6)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=1, b=1, c=6")
	}
}

func TestComposition2(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(2), big.NewInt(-1), big.NewInt(3))
	form2, _ := NewBQuadraticForm(big.NewInt(2), big.NewInt(-1), big.NewInt(3))

	Droot4th := big.NewInt(2)
	got := form1.Composition(form2, Droot4th)

	if got.a.Cmp(big.NewInt(2)) != 0 || got.b.Cmp(big.NewInt(1)) != 0 || got.c.Cmp(big.NewInt(3)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=2, b=1, c=3")
	}
}

func TestComposition3(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(2), big.NewInt(1), big.NewInt(3))
	form2, _ := NewBQuadraticForm(big.NewInt(2), big.NewInt(1), big.NewInt(3))

	Droot4th := big.NewInt(2)
	got := form1.Composition(form2, Droot4th)

	if got.a.Cmp(big.NewInt(2)) != 0 || got.b.Cmp(big.NewInt(-1)) != 0 || got.c.Cmp(big.NewInt(3)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=2, b=-1, c=3")
	}
}

func TestComposition4(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(2), big.NewInt(-1), big.NewInt(3))
	form2, _ := NewBQuadraticForm(big.NewInt(2), big.NewInt(1), big.NewInt(3))

	Droot4th := big.NewInt(2)
	got := form1.Composition(form2, Droot4th)

	if got.a.Cmp(big.NewInt(1)) != 0 || got.b.Cmp(big.NewInt(1)) != 0 || got.c.Cmp(big.NewInt(6)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=1, b=1, c=6")
	}
}

func TestComposition5(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(31), big.NewInt(24), big.NewInt(15951))
	form2, _ := NewBQuadraticForm(big.NewInt(31), big.NewInt(24), big.NewInt(15951))

	root4th := big.NewInt(26)
	got := form1.Composition(form2, root4th)

	if got.a.Cmp(big.NewInt(517)) != 0 || got.b.Cmp(big.NewInt(100)) != 0 || got.c.Cmp(big.NewInt(961)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=517, b=100, c=961")
	}
}

func TestComposition6(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(142), big.NewInt(130), big.NewInt(3511))
	form2, _ := NewBQuadraticForm(big.NewInt(41), big.NewInt(0), big.NewInt(12057))

	root4th := big.NewInt(26)
	got := form1.Composition(form2, root4th)

	if got.a.Cmp(big.NewInt(566)) != 0 || got.b.Cmp(big.NewInt(-550)) != 0 || got.c.Cmp(big.NewInt(1007)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=566, b=-550, c=1007")
	}
}

func TestComposition7(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(142), big.NewInt(130), big.NewInt(3511))
	form2, _ := NewBQuadraticForm(big.NewInt(677), big.NewInt(664), big.NewInt(893))

	root4th := big.NewInt(26)
	got := form1.Composition(form2, root4th)
	if got.a.Cmp(big.NewInt(591)) != 0 || got.b.Cmp(big.NewInt(564)) != 0 || got.c.Cmp(big.NewInt(971)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=591, b=564, c=971")
	}
}

// Compute the square of a binary quadratic form.
func TestSquare1(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(1), big.NewInt(6))

	root4th := big.NewInt(2)
	got := form1.square(root4th)

	if got.a.Cmp(big.NewInt(1)) != 0 || got.b.Cmp(big.NewInt(1)) != 0 || got.c.Cmp(big.NewInt(6)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=1, b=1, c=6")
		t.Error("Unexpected Result", "got", got, "expected:a=", "1", "b=", "1", "c=", "6")
	}
}

func TestSquare2(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(19), big.NewInt(18), big.NewInt(26022))

	root4th := big.NewInt(26)
	got := form1.square(root4th)
	got.Reduction()

	if got.a.Cmp(big.NewInt(361)) != 0 || got.b.Cmp(big.NewInt(-286)) != 0 || got.c.Cmp(big.NewInt(1426)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=361, b=-286, c=26022")
	}
}

func TestSquare3(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(19), big.NewInt(-12), big.NewInt(262))

	root4th := big.NewInt(11)
	got := form1.square(root4th)
	got.Reduction()

	if got.a.Cmp(big.NewInt(46)) != 0 || got.b.Cmp(big.NewInt(-32)) != 0 || got.c.Cmp(big.NewInt(113)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=46, b=-32, c=113")
	}
}

func TestSquare4(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(31), big.NewInt(24), big.NewInt(15951))

	root4th := big.NewInt(26)
	got := form1.square(root4th)
	got.Reduction()

	if got.a.Cmp(big.NewInt(517)) != 0 || got.b.Cmp(big.NewInt(100)) != 0 || got.c.Cmp(big.NewInt(961)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=517, b=100, c=961")
	}
}

func TestSquare5(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(517), big.NewInt(100), big.NewInt(961))

	root4th := big.NewInt(26)
	got := form1.square(root4th)

	if got.a.Cmp(big.NewInt(529)) != 0 || got.b.Cmp(big.NewInt(-378)) != 0 || got.c.Cmp(big.NewInt(1002)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=529, b=-378, c=1002")
	}
}

func TestSquare6(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(3), big.NewInt(-2), big.NewInt(176081))

	root4th := big.NewInt(19)
	got := form1.square(root4th)

	if got.a.Cmp(big.NewInt(9)) != 0 || got.b.Cmp(big.NewInt(4)) != 0 || got.c.Cmp(big.NewInt(58694)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=9, b=4, c=58694")
	}
}

func TestSquare7(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(729), big.NewInt(626), big.NewInt(859))

	root4th := big.NewInt(26)
	got := form1.square(root4th)

	if got.a.Cmp(big.NewInt(419)) != 0 || got.b.Cmp(big.NewInt(-412)) != 0 || got.c.Cmp(big.NewInt(1362)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=419, b=-412, c=1362")
	}
}

func TestCube(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(31), big.NewInt(24), big.NewInt(15951))

	root4th := big.NewInt(26)
	got := form1.cube(root4th)

	if got.a.Cmp(big.NewInt(286)) != 0 || got.b.Cmp(big.NewInt(54)) != 0 || got.c.Cmp(big.NewInt(1731)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=286, b=54, c=1731")
	}
}

func TestCube2(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(19), big.NewInt(18), big.NewInt(26022))

	root4th := big.NewInt(26)
	got := form1.cube(root4th)

	if got.a.Cmp(big.NewInt(79)) != 0 || got.b.Cmp(big.NewInt(38)) != 0 || got.c.Cmp(big.NewInt(6262)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=79, b=38, c=6262")
	}
}

func TestCube3(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(22), big.NewInt(6), big.NewInt(225))

	root4th := big.NewInt(8)
	got := form1.cube(root4th)

	if got.a.Cmp(big.NewInt(70)) != 0 || got.b.Cmp(big.NewInt(54)) != 0 || got.c.Cmp(big.NewInt(81)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=70, b=54, c=81")
	}
}

func TestCube4(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(19), big.NewInt(-12), big.NewInt(262))

	root4th := big.NewInt(8)
	got := form1.cube(root4th)

	if got.a.Cmp(big.NewInt(61)) != 0 || got.b.Cmp(big.NewInt(22)) != 0 || got.c.Cmp(big.NewInt(83)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=61, b=22, c=83")
	}
}

func TestCube5(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(46), big.NewInt(-32), big.NewInt(113))

	root4th := big.NewInt(8)
	got := form1.cube(root4th)

	if got.a.Cmp(big.NewInt(2)) != 0 || got.b.Cmp(big.NewInt(0)) != 0 || got.c.Cmp(big.NewInt(2471)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=2, b=0, c=2471")
	}
}

func TestCube6(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(3), big.NewInt(-2), big.NewInt(176081))

	root4th := big.NewInt(8)
	got := form1.cube(root4th)

	if got.a.Cmp(big.NewInt(27)) != 0 || got.b.Cmp(big.NewInt(22)) != 0 || got.c.Cmp(big.NewInt(19569)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=27, b=22, c=19569")
	}
}

// Compute the exponential of a binary quadratic form
func TestExp1(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(2), big.NewInt(1), big.NewInt(3))

	root4th := big.NewInt(2)
	got := form1.Exp(big.NewInt(6), root4th)

	if got.a.Cmp(big.NewInt(1)) != 0 || got.b.Cmp(big.NewInt(1)) != 0 || got.c.Cmp(big.NewInt(6)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=1, b=1, c=6")
	}
}

func TestExp2(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(31), big.NewInt(24), big.NewInt(15951))

	root4th := big.NewInt(26)
	got := form1.Exp(big.NewInt(200), root4th)

	if got.a.Cmp(big.NewInt(517)) != 0 || got.b.Cmp(big.NewInt(-276)) != 0 || got.c.Cmp(big.NewInt(993)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=517, b=-276, c=993")
	}
}

func TestExp3(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(31), big.NewInt(24), big.NewInt(15951))

	root4th := big.NewInt(26)
	got := form1.Exp(big.NewInt(200), root4th)

	if got.a.Cmp(big.NewInt(517)) != 0 || got.b.Cmp(big.NewInt(-276)) != 0 || got.c.Cmp(big.NewInt(993)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=517, b=-276, c=993")
	}
}

func TestExp4(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(78), big.NewInt(-52), big.NewInt(6781))

	root4th := big.NewInt(26)
	got := form1.Exp(big.NewInt(500), root4th)

	if got.a.Cmp(big.NewInt(738)) != 0 || got.b.Cmp(big.NewInt(-608)) != 0 || got.c.Cmp(big.NewInt(841)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=738, b=-608, c=841")
	}
}

func TestExp5(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(101), big.NewInt(38), big.NewInt(4898))

	root4th := big.NewInt(26)
	got := form1.Exp(big.NewInt(508), root4th)

	if got.a.Cmp(big.NewInt(66)) != 0 || got.b.Cmp(big.NewInt(54)) != 0 || got.c.Cmp(big.NewInt(7501)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=66, b=54, c=7501")
	}
}

func TestExp6(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(101), big.NewInt(38), big.NewInt(4898))

	root4th := big.NewInt(26)
	got := form1.Exp(big.NewInt(1), root4th)

	if got.a.Cmp(big.NewInt(101)) != 0 || got.b.Cmp(big.NewInt(38)) != 0 || got.c.Cmp(big.NewInt(4898)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=101, b=38, c=4898")
	}
}

func TestExp7(t *testing.T) {
	form1, _ := NewBQuadraticForm(big.NewInt(101), big.NewInt(38), big.NewInt(4898))

	root4th := big.NewInt(26)
	got := form1.Exp(big.NewInt(22999971), root4th)

	if got.a.Cmp(big.NewInt(101)) != 0 || got.b.Cmp(big.NewInt(38)) != 0 || got.c.Cmp(big.NewInt(4898)) != 0 {
		t.Error("Unexpected Result: a=", got.GetBQForma(), "b=", got.GetBQForma(), "c=", got.GetBQFormc(), "expected:a=101, b=38, c=4898")
	}
}

// Benchmark of basic operations: Exp, Composition, Reduction
func BenchmarkExp(b *testing.B) {
	form1, _ := NewBQuadraticForm(big.NewInt(78), big.NewInt(-52), big.NewInt(6781))
	root4th := big.NewInt(26)
	for i := 0; i < b.N; i++ {
		form1.Exp(big.NewInt(200000), root4th)
	}
}

func BenchmarkComposition(b *testing.B) {
	form1, _ := NewBQuadraticForm(big.NewInt(142), big.NewInt(130), big.NewInt(3511))
	form2, _ := NewBQuadraticForm(big.NewInt(41), big.NewInt(0), big.NewInt(12057))
	root4th := big.NewInt(26)
	for i := 0; i < b.N; i++ {
		form1.Composition(form2, root4th)
	}
}

func BenchmarkReduction(b *testing.B) {
	got, _ := NewBQuadraticForm(big.NewInt(4), big.NewInt(5), big.NewInt(3))

	for i := 0; i < b.N; i++ {
		got.Reduction()
	}
}

func BenchmarkIsDivideBy3(b *testing.B) {
	got := big.NewInt(9999823492)

	for i := 0; i < b.N; i++ {
		new(big.Int).Mod(got, bigThree)
	}
}

func BenchmarkIsDivideBy31(b *testing.B) {
	var BIGFIELDORDER = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
	var bigPrime, _ = new(big.Int).SetString(BIGFIELDORDER, 10)
	for i := 0; i < b.N; i++ {
		expansion23StrictChains(bigPrime, 16)
	}
}
