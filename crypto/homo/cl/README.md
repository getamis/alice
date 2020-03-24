# Castagnos and Laguillaumie homomorphic Scheme

A linearly homomorphic encryption scheme whose security relies on the hardness of the decisional Diffie-Hellman problem. This Golang library implements the scheme in [CL15](https://pdfs.semanticscholar.org/fba2/b7806ea103b41e411792a87a18972c2777d2.pdf?_ga=2.188920107.1077232223.1562737567-609154886.1559798768)<sup>[1]</sup>.


## Guildline

This Library offers 5 public functions: **NewCL, Encrypt, Decrypt, Add, MulConst**.

### Example

    var BIG_FIELD_ORDER = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
    var bigPrime, _ = new(big.Int).SetString(BIG_FIELD_ORDER, 10)
    var SAFE_PARAMETER = 1348
    var cl *CL

    // Generate a private key and the corresponding public key.
    cl, _ = NewCL(big.NewInt(1024), 40, bigPrime, safeParameter, 40)

    // Encrypt two plaintexts by the public key
    plaintext1 := big.NewInt(3)
    cipherMessege1, _ := cl.Encrypt(plaintext1.Bytes())

    plaintext2 := big.NewInt(13)
    cipherMessege2, _ := cl.Encrypt(plaintext2.Bytes())

    // Do an operation of cipherMessege1 and cipherMessege2.
    sum, _ := cl.Add(cipherMessege1, cipherMessege2)

    // The result should be 3 + 13 = 16
    decyptAddResult, _ := cl.Decrypt(sum)

    // Do a scalar multiplication for cipherMessege1.
    scalar := big.NewInt(5)
    scalarResult, _ := cl.MulConst(cipherMessege1, scalar)

    // The result should be 5 * 3 = 15
    decyptscalarResult, _ := cl.Decrypt(scalarResult)

    fmt.Println("The decryption of adding cipherMessege1 and cipherMessege2 to be", decyptAddResult)
    fmt.Println("The decryption of cipherMessege1 by multiplying the scalar is", decyptscalarResult)



**Remark:** 
1. Generally speaking, the larger safeParameter is safer<sup>[Security Level]</sup>.
2. We improve the efficiency of this library. The following benchmarks are out of date.



## Experiment

Our benchmarks were in local computation and ran on an Intel qualcore-i5 CPU 2.3 GHz and 16GB of RAM.

### Security Level

The Table below is referenced by [Improved Efficiency of a Linearly Homomorphic Cryptosystem](https://link.springer.com/chapter/10.1007/978-3-030-16458-4_20).

```
+-----------------+---------------+------------------------------+
| Security Level  |  RSA modulus  |  fundamental discriminant ΔK |
+-----------------+---------------+------------------------------+
|          112    |          2048 |                         1348 |
|          128    |          3072 |                         1828 |
|          192    |          7680 |                         3598 |
|          256    |         15360 |                         5972 |
+-----------------+---------------+------------------------------+
```

### Benchmark

```
+---------------+--------------------+-------------------+--------------------+--------------------+
|  Operation    |  Message space (256 bit)                                                         |
+---------------+--------------------+-------------------+--------------------+--------------------+
| Discriminant  |  1348 bit          | 1828 bit          | 3598 bit           | 5972 bit           |
| Encryption    |  0.18055360 s/op   | 0.28993402 s/op   | 1.023070955 s/op   | 2.942373759 s/op   |
| Decryption    |  0.10738896 s/op   | 0.20586519 s/op   | 1.562096359 s/op   | 4.416983586 s/op   |
| Add           |  0.24509818 s/op   | 0.57579160 s/op   | 3.016294212 s/op   |  -                 |
| EvalMul       |  0.34500619 s/op   | 0.55289621 s/op   | 2.368093142 s/op   |  -                 |
+---------------+--------------------+-------------------+--------------------+--------------------+
```

## Reference

1. [Linearly Homomorphic Encryption from DDH](https://pdfs.semanticscholar.org/fba2/b7806ea103b41e411792a87a18972c2777d2.pdf?_ga=2.188920107.1077232223.1562737567-609154886.1559798768)

## Other Library

1. [Class Groups](https://github.com/KZen-networks/class-groups)