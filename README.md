
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

HTSS  has been developed by [Tassa](https://www.openu.ac.il/lists/mediaserver_documents/personalsites/tamirtassa/hss_conf.pdf) and other researchers many years ago. In our implementation, we setup up this theory on TSS(i.e. just replace Lagrange Interpolation to Birkhoff Interpolation).

Now, Alice supports two parts:
## Audited Part :

### ECDSA :
1. [HTSS(A variant of GG18 and CCLST)](./crypto/tss/ecdsa/README.md).
2. [HTSS(A variant of CGGMP)](./crypto/tss/ecdsa/README.md).


### EdDSA :
1. [HTSS(A variant of FROST)](./crypto/tss/eddsa/frost/README.md).


## Preparation : 
1. [2-party Bip32](./crypto/bip32/README.md).


## Audit Report:
 Alice has been audited by [Kudelski Security](https://www.kudelskisecurity.com). 
1. (GG18 And CCLST) The details can be found in [here](./REPORT_2020-05-19.pdf).
    
    Algorithm: The algorithms can be downloaded in [here](./GG18AndCCLST.pdf).
2. (FROST And CGGMP) The details can be found in [here](./REPORT_2022.pdf).


### Warning:
Although the fist part of Alice has been audited, you should still be careful to use it. 
1. Using end-to-end encryption to transfer messages between two parties is necessary. 
2. If any error messages occur during execution Alice, you should stop and restart it. **Never restart in the middle flow.**
3. Now, the version of our GG18 is secure according to Theorem 2 in the [GG18](https://eprint.iacr.org/2019/114.pdf). We follow the suggestion of GG18 to substitute sMTA for mta and mta with check.


If you have more questions, you can connect [us](https://www.am.is/) directly without any hesitation.

### Our product
Wallet: [Qubic](https://www.qubic.app/en.html)


## The Explanation of Packages
1. **binaryfield**: support some basic operation of binary fields.
2. **binaryquadratic**: support operations  ideal class groups of quadratic imaginary fields over the rational number Q (ref.[here](https://math.stanford.edu/~conrad/676Page/handouts/picgroup.pdf)).
3. **bip32**: support two-party computation of [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
4. **birkhoffinterpolation**: support the [birkhoff interpolation](https://en.wikipedia.org/wiki/Birkhoff_interpolation) (i.e. a generization of Lagrange interpolation).
5. **circuit**: support the loading of [bristol fashion](https://homes.esat.kuleuven.be/~nsmart/MPC/) and garbling circuit (ref. [Two Halves Make a Whole: Reducing Data Transfer in Garbled Circuits using Half Gates](https://eprint.iacr.org/2014/756)).
6. **commitment**: support [Section 2.4: hash commitment](https://eprint.iacr.org/2019/114.pdf), [Section 2.6:Feldman’s VSS parotocol](https://eprint.iacr.org/2019/114.pdf), and [Pedersen Commitment](https://research.nccgroup.com/2021/06/15/on-the-use-of-pedersen-commitments-for-confidential-payments/).
7. **dbnssystem**: write a positive integer to be [The Double-Base Number expression](https://link.springer.com/chapter/10.1007/978-3-540-70500-0_32).
8. **ecpointgrouplaw**: an interface of group operations of elliptic curve groups.
9. **elliptic**: support groups of of elliptic curve groups.
10. **homo**: support additive homomorphic encryptions: [Castagnos and Laguillaumie homomorphic Scheme](https://github.com/getamis/alice/tree/master/crypto/homo/cl) and [Paillier homomorphic cryptosystem](https://github.com/getamis/alice/tree/master/crypto/homo/paillier).
11. **matrix**: support some operations of matrices over finite fields.
12. **mta**: the special package used in the sign algorithm of ECDSA.
13. **oprf**: support a hash function mapping to the points of secp256k1. (ref. [Shallue-van de Woestijne Method: Hashing to Elliptic Curves](https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.9.1))
14. **ot**: support an [Oblivious transfer](https://en.wikipedia.org/wiki/Oblivious_transfer) protocol (ref. [our implementation: Blazing Fast OT for Three-round UC OT Extension](https://link.springer.com/chapter/10.1007/978-3-030-45388-6_11)).
15. **polynomial**: support some operations of polynomials over finite fields.
16. **tss**: support ECDSA: [GG18](https://eprint.iacr.org/2019/114.pdf), [CCLST](https://link.springer.com/chapter/10.1007/978-3-030-45388-6_10), and [CGGMP](https://eprint.iacr.org/2021/060). And EdDSA: [FROST](https://link.springer.com/chapter/10.1007/978-3-030-81652-0_2).
17. **utils**: support some commonly used functions.
18. **zkrpoof**: support some zero knowledge proofs e.x. Schnorr's proof, factorization proof and so on.



## Acknowledgments:
Thanks to 
1. [Filipe Casal from Trail of Bits](https://www.trailofbits.com) for indicating the potential issues of integer factorization proof.
2. [Coinbase Developer grant](https://www.coinbase.com/blog/announcing-our-second-developer-grant-winners)