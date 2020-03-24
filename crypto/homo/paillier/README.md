# Paillier homomorphic cryptosystem

A partial homomorphic encryption scheme whose security relies on the hardness of the integer factorization. This Golang library implements the scheme.


## Guildline

This Library offers main 5 public functions: **NewPaillier, Encrypt, Decrypt, Add, MulConst**.

### Example
    var keySize = 2048 
    
    // Generate a private key and the corresponding public key.
    p, _ = NewPaillier(keySize)

	m1 := big.NewInt(100)
	m2 := big.NewInt(200)
	c1, _ := p.Encrypt(m1.Bytes())
	c2, _ := p.Encrypt(m2.Bytes())
	sum, _ := p.PublicKey.Add(c1, c2)
	// The output is 300 = 100 + 200.
	decryptSum, _ := p.Decrypt(sum)

	m := big.NewInt(100)
	scalar := big.NewInt(50)
	c, _ := p.Encrypt(m.Bytes())
	mulConst, _ := p.PublicKey.MulConst(c, scalar)
	// The output is 5000 = 100 * 50.
	decryptResult, _ := p.Decrypt(mulConst)

	fmt.Println("The decryption of adding m1 and m2 to be", decryptSum)
    fmt.Println("The decryption of m by multiplying the scalar is", decryptResult)

   

**Remark**: 
1. Generally speaking, the larger keySize is safer<sup>[Security Level]</sup>.


## Experiment

Our benchmarks were in local computation and ran on an Intel qualcore-i5 CPU 2.3 GHz and 16GB of RAM.

### Security Level

The Table below is referenced by [Improved Efficiency of a Linearly Homomorphic Cryptosystem](https://link.springer.com/chapter/10.1007/978-3-030-16458-4_20).

```
+-----------------+---------------+
| Security Level  |  RSA modulus  |
+-----------------+---------------+
|          112    |          2048 |
|          128    |          3072 |
|          192    |          7680 |
|          256    |         15360 |
+-----------------+---------------+
```

### Benchmark

```
+---------------+--------------------+-------------------+--------------------+--------------------+
|  Operation    |  Message space (256 bit)                                                         |
+---------------+--------------------+-------------------+--------------------+--------------------+
| Discriminant  |  2048 bit          | 3072 bit          | 7680 bit           | 15360 bit          |
| Encryption    |  16.42 ms/op       | 551.80 ms/op      | 21.56 s/op         |  _                 |
| Decryption    |  15.93 ms/op       | 678.46 ms/op      | 27.22 s/op         |  _                 |
| Add           |  0.013 ms/op       | 394    ms/op      | 3.081 s/op         |  -                 |
| EvalMul       |  0.345 ms/op       | 1095.05 ms/op     | 11.733 s/op        |  -                 |
+---------------+--------------------+-------------------+--------------------+--------------------+
```

## Reference

1. [Public-Key Cryptosystems Based on Composite Degree Residuosity Classes](https://link.springer.com/chapter/10.1007%2F3-540-48910-X_16)

2. [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem)

## Other Library
1. [A library for Partially Homomorphic Encryption in Python](https://github.com/n1analytics/python-paillier)
2. [A Go implementation of the partially homomorphic Paillier Cryptosystem.](https://github.com/Roasbeef/go-go-gadget-paillier)
3. [A pure-Rust implementation of the Paillier encryption scheme](https://github.com/mortendahl/rust-paillier)
4. [Javascript proof-of-concept implementation of the Paillier cryptosystem ](https://github.com/mhe/jspaillier)
</br>
..... and so on.