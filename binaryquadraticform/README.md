# Class groups

This library implemented class groups of imaginary quadratic fields by the operations of binary quadratic forms<sup>[1]</sup>.


## Guildline

The main public functions in this Library are: **Reduction, Exp, Composition**. 

### Example

    package binaryquadraticform

    import (
	    "math/big"
    	"testing"
    )

    // Reduction
    func TestReducedForm(t *testing.T) {

	    got, _ := NewBQuadraticForm(big.NewInt(33), big.NewInt(11), big.NewInt(5))
	    got.Reduction()

        // output: a=5, b= -1, c= 27
    }

    // Composition
    func TestComposition(t *testing.T) {
	    form1, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(1), big.NewInt(6))
	    form2, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(1), big.NewInt(6))

	    Droot4th := big.NewInt(2)
	    got := form1.Composition(form2, Droot4th)

        // output: a=1, b=1, c=6
    }

    // Exp
    func TestExp(t *testing.T) {
	    form1, _ := NewBQuadraticForm(big.NewInt(31), big.NewInt(24), big.NewInt(15951))

	    root4th := big.NewInt(26)
	    got := form1.Exp(big.NewInt(200), root4th)
        // output: a=517, b=-276, c=993
    }


## Experiment

Our benchmarks were in local computation and ran on an Intel qualcore-i5 CPU 2.3 GHz and 16GB of RAM.

### Benchmark
We use a particular binary qudatatic Q := ax^2+bxy+cy^2 form to benchmark, where </br>
a=2   </br>
b=1  </br>
c=38270086293509404933867071895401019019366095470206334878396235822253000046664893060272814
4885376377736899019811788016480970822740602470345900972511577261040787881052139208590201529
5545562523958711866779371531088132889638114041946661849770572154226710985917599916457066302
6821483359097065850719591509598145462062654351033736734969435747887449357951781277325201275
3107597915953828936546637318213715877938209264724667965717193550712672887897192948921266890
8199079072163111583975633638661816714659180109107951783005735418950482497851235754121794548
776139119565032459702128377126838952995785769100706778680652441494512278   </br>
</br>
Discriminant =  2048 bit</br>


```
+---------------+--------------------+-------------------+--------------------+--------------------+
|  Operation    |                                                                                  |
+---------------+--------------------+-------------------+--------------------+--------------------+
| Exponential   |  100 bit           | 200 bit           | 300 bit            | 400 bit            |
| Exp           |  5.6179 ms/op      | 11.2084 ms/op     | 23.4616 ms/op      | 21.5768 ms/op      |
+---------------+--------------------+-------------------+--------------------+--------------------+
```
</br>

We benchmark the redunction, square, cube, composition for Q^100.
```
+---------------+--------------------+
|  Operation    |                    |                                                              
+---------------+--------------------+
| Reduction     |  89 ns/op          |
| square        |  6734 ns/op        | 
| cube          |  10787 ns/op       | 
| composition   |  7737 ns/op        | 
+---------------+--------------------+
```



## Reference:

1. [Cohen's book:A Course in Computational Algebraic Number Theory](https://www.amazon.com/Course-Computational-Algebraic-Graduate-Mathematics/dp/3540556400)
2. [Maxwell Sayles](https://github.com/maxwellsayles/)

## Other Library:

1. [Class Groups](https://github.com/KZen-networks/class-groups)
2. [Cryptographic accumulators in Rust](https://github.com/cambrian/accumulator)