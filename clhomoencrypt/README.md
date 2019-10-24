# Castagnos and Laguillaumie cryptosystem

A linearly homomorphic encryption scheme whose security relies on the hardness of the decisional Diffie-Hellman problem. This Golang library implements the scheme in [CL15](https://pdfs.semanticscholar.org/fba2/b7806ea103b41e411792a87a18972c2777d2.pdf?_ga=2.188920107.1077232223.1562737567-609154886.1559798768)<sup>[1]</sup>.


## Guildline

This Library offers 5 public functions: **PubKeygen, Encrypt, Decrypt, EvalAdd, EvalMulConst**.

### Example

    var BIG_FIELD_ORDER = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
    var bigPrime, _ = new(big.Int).SetString(BIG_FIELD_ORDER, 10)
    var SAFE_PARAMETER = 1348

    // Generate a private key and the corresponding public key.
    var publicKey, privateKey, _ = PubKeygen(bigPrime, SAFE_PARAMETER)

    // Encrypt two plaintexts by the public key
    plaintext1 := big.NewInt(3)
	cipherMessege1 := Encrypt(publicKey, plaintext1)

    plaintext2 := big.NewInt(13)
    cipherMessege2 := Encrypt(publicKey, plaintext2)

    // Do a operation of cipherMessege1 and cipherMessege2.
    AddResult := EvalAdd(cipherMessege1, cipherMessege2, publicKey)

    // The result should be 3 + 13 = 16
    decyptAddResult := Decrypt(AddResult, privateKey)

    // Do a scalar multiplication for cipherMessege1.
    scalar := big.NewInt(5)
    scalarResult := EvalMulConst(cipherMessege1  , scalar, publicKey)

    // The result should be 5 * 3 = 15
    decyptscalarResult := Decrypt(scalarResult, privateKey)

    fmt.Println("The decryption of adding cipherMessege1 and cipherMessege1 to be", decyptAddResult)
    fmt.Println("The decryption of cipherMessege1 by multiplying the scalar is", decyptscalarResult)



**Remark**: Generally speaking, the larger safeParameter is safer<sup>[Security Level]</sup>.



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
| Encryption    |  180553607 ns/op   | 289934024 ns/op   | 1023070955 ns/op   | 2942373759 ns/op   |
| Decryption    |  117321847 ns/op   | 205865198 ns/op   | 1562096359 ns/op   | 4416983586 ns/op   |
| Add           |  245098188 ns/op   | 575791606 ns/op   | 3016294212 ns/op   |  -                 |
| EvalMul       |  282251407 ns/op   | 552896219 ns/op   | 2209920746 ns/op   |  -                 |
+---------------+--------------------+-------------------+--------------------+--------------------+
```

## Reference:

1. [Linearly Homomorphic Encryption from DDH](https://pdfs.semanticscholar.org/fba2/b7806ea103b41e411792a87a18972c2777d2.pdf?_ga=2.188920107.1077232223.1562737567-609154886.1559798768)

## Other Library:

1. [Class Groups](https://github.com/KZen-networks/class-groups)