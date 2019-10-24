# Class groups

This library implemented class groups of imaginary quadratic fields by the operations of binary quadratic forms<sup>[1]</sup>.


## Guildline

The main public functions in this Library are: **Reduction, Exp, Composition**. 

### Example

    var FORMCSTRING = "38270086293509404933867071895401019019366095470206334878396235822253000046664893060272814488"+
	"537637773689901981178801648097082274060247034590097251157726104078788105213920859020152955455"+
	"625239587118667793715310881328896381140419466618497705721542267109859175999164570663026821483"+
	"359097065850719591509598145462062654351033736734969435747887449357951781277325201275310759791"+
	"595382893654663731821371587793820926472466796571719355071267288789719294892126689081990790721"+
	"631115839756336386618167146591801091079517830057354189504824978512357541217945487761391195650"+
	"32459702128377126838952995785769100706778680652441494512278"
    var FORMC, _ = new(big.Int).SetString(FORMCSTRING, 10)

    // Generate a binary quadratic form
    var	FORMBENCHMARK, _ = NewBQuadraticForm(big.NewInt(2), big.NewInt(1), new(big.Int).Set(FORMC))

    // Prepare to compute square, cube, composition. Need to compute [|Disc|/4], where [] is the floor function and  Disc = b^2-4ac
    disc := new(big.Int).Set(FORMBENCHMARK.GetBQFormDiscriminant())
	disc.Abs(disc)
    root4th := new(big.Int).Sqrt(disc)
	root4th.Sqrt(root4th)

    // Composition: FORMBENCHMARK * FORMBENCHMARK100
    FORMBENCHMARK.Composition(FORMBENCHMARK100, root4th)

    // Exp: in this case, the outcome is FORMBENCHMARK^(1267650600228229401496704464915).
    var orderString = "1267650600228229401496704464915"
	var bigorder, _ = new(big.Int).SetString( orderString, 10)
    FORMBENCHMARK.Exp(bigorder, root4th)

    // Reduction: the best representatives of a binary quadratic form.
    FORMBENCHMARK.Reduction()

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
| Exp           |  7.3714 ms/op      | 15.8545 ms/op     | 22.7846 ms/op      | 30.93325 ms/op     |
+---------------+--------------------+-------------------+--------------------+--------------------+
```
</br>

We benchmark the redunction, square, cube, composition for Q^100.
```
+---------------+--------------------+
|  Operation    |                    |                                                              
+---------------+--------------------+
| Reduction     |  125 ns/op         |
| square        |  56134 ns/op       | 
| cube          |  106829 ns/op      | 
| composition   |  58114 ns/op       | 
+---------------+--------------------+
```



## Reference:

1. [Cohen's book:A Course in Computational Algebraic Number Theory](https://www.amazon.com/Course-Computational-Algebraic-Graduate-Mathematics/dp/3540556400)
2. [Maxwell Sayles](https://github.com/maxwellsayles/)

## Other Library:

1. [Class Groups](https://github.com/KZen-networks/class-groups)
2. [Cryptographic accumulators in Rust](https://github.com/cambrian/accumulator)