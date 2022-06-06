
# Hierarchical Threshold Signature Scheme
[![Apache licensed][1]][2] [![Go Report Card][3]][4] [![Build Status][5]][6] [![codecov][7]][8]

[1]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[2]: LICENSE
[3]: https://goreportcard.com/badge/github.com/getamis/alice
[4]: https://goreportcard.com/report/github.com/getamis/alice
[5]: https://travis-ci.com/getamis/alice.svg?branch=master
[6]: https://travis-ci.com/getamis/alice
[7]: https://codecov.io/gh/getamis/alice/branch/master/graph/badge.svg
[8]: https://codecov.io/gh/getamis/alice

## Introduction:

This is Hierarchical Threshold Signature Scheme (HTSS) worked by [AMIS](https://www.am.is). Comparing to Threshold Signature Scheme (TSS), shares in this scheme are allowed to have different ranks.

The main merit of HTSS is vertical access control such that it has "partial accountability”. Although TSS achieves joint control to disperse risk among the participants, the level of all shares are equal. It is impossible to distinguish which share getting involved in an unexpected signature. TSS is not like the multi-signature scheme as the signature is signed by distinct private keys in multi-signature scheme. It is because Shamir’s secret sharing only supports horizontal access control.

For example, an important contract not only requires enough signatures, but also needs to be signed by a manager. Despite the fact that vertical access control can be realized on the application layer and tracked by an audit log. Once a hack happens, we will have no idea about who to blame for. However, in HTSS framework, through assigning different ranks of each share induces that any valid signature generated includes the share of the manager.

HTSS  has been developed by [Tassa](https://www.openu.ac.il/lists/mediaserver_documents/personalsites/tamirtassa/hss_conf.pdf) and other researchers many years ago. In our implementation, we setup up this theory on TSS(i.e. just replace Lagrange Interpolation to Birkhoff Interpolation).  Meanwhile, our protocol of sign (i.e. GG18 and CCLST20 ) can support two homomorphic encryptions which are Paillier and CL scheme. 

Now, Alice supports two parts:
### Audited Part :

1. [HTSS(A variant of GG18 and CCLST): ECDSA](./crypto/tss/ecdsa/gg18/README.md).

### Preparation : 
1. [HTSS(A variant of CGGMP): ECDSA](./crypto/tss/ecdsa/cggmp/README.md).
2. [HTSS(A variant of FROST): EdDSA](./crypto/tss/eddsa/frost/README.md).
3. [2-party Bip32](./crypto/bip32/README.md).



## Warning:
Although the fist part of Alice has been audited, you should still be careful to use it. 
1. Using end-to-end encryption to transfer messages between two parties is necessary. 
2. If any error messages occur during execution Alice, you should stop and restart it. **Never restart in the middle flow.**
3. **(IMPORTANT)** Now, GG18 is insecure, so you SHOULD replace Paillier homomorphic encryption into CL homomorphic encryption (i.e. USE CCLST protocol). Our version is the fast version of GG18 (i.e. without range proofs). The merit of CL homomorphic encryption does not any range proofs.


If you have more questions, you can connect [us](https://www.am.is/) directly without any hesitation.

<h3 id="usefulLibrary">Useful Cryptography Libraries in this Repository:</h3>

1. [Binary quadratic forms for class groups of imaginary quadratic fields](https://github.com/getamis/alice/tree/master/crypto/binaryquadraticform)
2. [Castagnos and Laguillaumie homomorphic Scheme](https://github.com/getamis/alice/tree/master/crypto/homo/cl)
3. [Paillier homomorphic cryptosystem](https://github.com/getamis/alice/tree/master/crypto/homo/paillier)


## Acknowledgments:
Thanks to 
1. [Filipe Casal from Trail of Bits](https://www.trailofbits.com) for indicating the potential issues of integer factorization proof.