
# 2-Party Bip32

## Introduction:

[Bip32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) describes hierarchical deterministic wallets, which can be shared partially or entirely with different systems, each with or without the ability to spend coins. This technique has been used in the blockchain world widely.

This library basing on "Garbled Circuit" offers an MPC 2-2 method to produce master-key shares and the associated child key shares without recovering any private keys. Moreover, the produced shares are compatible with our HTSS Library.

## Warning:
This library has **Not** been audited. If you want to use it at your own risk.


## Table of Contents:

*	[Implementations](#implementation)
	*	[Garble Circuit](#Garblecircuit)
    *	[OT](#OT)
	*	[2-party Bip32](#Bip32)
		*	[Seed](#Seed)
		*	[ChildShare](#childshare)
*	[Examples](#Examples)
*	[References](#reference)
*	[Other Libraries](#Libraries)


<h2 id="implementation">Implementations:</h2>

This library is consist of Garble Circuit, OT, and Bip32.


<h3 id="Garblecircuit">Garble circuit:</h3>

[Garbled circuit](https://en.wikipedia.org/wiki/Garbled_circuit) is a cryptographic protocol that enables two-party secure computation in which two mistrusting parties can jointly evaluate a function over their private inputs without the presence of a trusted third party. 

We implement the "Garbled Circuit" according to the paper: [Two Halves Make a Whole Reducing data Transfer in Garbled Circuits using Half Gates](https://eprint.iacr.org/2014/756.pdf) and improve its security according to the paper [Better Concrete Security for Half-Gates Garbling](https://eprint.iacr.org/2019/1168.pdf).
The used boolean circuit is [Bristol fashion](https://homes.esat.kuleuven.be/~nsmart/MPC/).

In this library, we construct two special boolean circuits:
1. [MPCSEED](https://github.com/getamis/alice/tree/master/crypto/circuit/bristolFashion/MPCSEED.txt)
2. [MPCHMAC](https://github.com/getamis/alice/tree/master/crypto/circuit/bristolFashion/MPCHMAC.txt)


<h3 id="OT">OT:</h3>

Our implementation are based on [Blazing Fast OT for Three-Round UC OT Extension](https://eprint.iacr.org/2020/110.pdf).


<h2 id="Bip32">2-party Bip32:</h2>

We offer two protocols here and explain these as follows. 

**Note**

In this version, we assume that the security model is "Semi-Honest": 
[Semi-Honest (Passive) Security](https://en.wikipedia.org/wiki/Secure_multi-party_computation): In this case, it is assumed that corrupted parties merely cooperate to gather information out of the protocol, but do not deviate from the protocol specification. This is a naive adversary model, yielding weak security in real situations. However, protocols achieving this level of security prevent inadvertent leakage of information between (otherwise collaborating) parties, and are thus useful if this is the only concern. In addition, protocols in the semi-honest model are quite efficient, and are often an important first step for achieving higher levels of security.

<h3 id="Seed">Seed:</h3>

There are two roles in our protocol called Alice and Bob.
Alice and Bob will choose own seed called AliceSeed and BobSeed respectively. Then after the the protocol, Alice (resp. Bob) will get her(resp. his) share.

Briefly describe the idea:
1. Alice chooses a secret seed s_A and a secret random value r_A and Bob also chooses a secret seed s_B and a secret random value r_B. 
2. Two parties perform garbled circuits with inputs s_A, s_B, r_A and r_B to learn own result. 
Alice learns m_A := I_L + r_B mod N and Bob learns m_B := I_L + r_A mod N. (Note: Alice(resp. Bob) does not know I_L and r_B(resp. r_A).) Here I = I_L || I_R = HMAC512("Bitcoin seed",s_A||S_B) and
N is the order of the elliptic curve group of secp256k1.
3. Applying hash commitments can fix the values m_A * G , m_B * G, r_B * G and r_A *G. These data can determine the public key P := m_A * G - r_B * G = m_B * G - r_A *G.
(Note that: P = parse_256(I_L)).

More details can be found in [here](https://github.com/getamis/alice/tree/master/Bip32SimpleFlow.pdf).

**Remark:**

1. The private seed is AliceSeed || BobSeed. Here || means "concatenate".
2. In our setting, the bit length of AliceSeed and BobSeed are both 256. Therefore, the corresponding "seed" is always 512 bit.



<h3 id="ChildShare">ChildShare:</h3>
The difficult part here is 
the case: hardened key.
There are still two roles in our protocol called Alice and Bob.
Alice (resp. Bob) uses her(resp. his) private input(i.e. share) to compute the own children share. And they can use children share as inputs of our TSS-sign to sign a transaction. In these processes, any private keys do not be recovered.


Briefly describe idea:
1. Two parties use the protocol Quid Pro Quo-tocols: Strengthening Semi-Honest Protocols with Dual Execution to lean the HMAC512(chain-cdoe, "private key").
The Quid Pro Quo-tocols can guarantee two parties learning the same output. 



<h2 id="Examples">Examples:</h2>
If you are interested in it, please see our tests:

1. [Seed Part](https://github.com/getamis/alice/tree/master/crypto/bip32/master/master_test.go).
2. [Child share Part](https://github.com/getamis/alice/tree/master/crypto/bip32/child/child_test.go).

<h2 id="reference">References:</h2>

1. [Two Halves Make a Whole Reducing data Transfer in Garbled Circuits using Half Gates](https://eprint.iacr.org/2014/756.pdf)
2. [Better Concrete Security for Half-Gates Garbling](https://eprint.iacr.org/2019/1168.pdf)
3. [Bristol fashion](https://homes.esat.kuleuven.be/~nsmart/MPC/)
4. [Blazing Fast OT for Three-Round UC OT Extension](https://eprint.iacr.org/2020/110.pdf)
5. [Quid Pro Quo-tocols: Strengthening Semi-Honest Protocols with Dual Execution](https://www.cs.umd.edu/~jkatz/papers/SP12.pdf)
6. [TinyGarble](https://github.com/esonghori/TinyGarble)
7. [Secure multi-party computation](https://en.wikipedia.org/wiki/Secure_multi-party_computation)
8. [JIGG](https://github.com/multiparty/jigg)


<h2 id="Libraries">Other Libraries:</h2>

1. [SPDZ-2](https://github.com/bristolcrypto/SPDZ-2)
2. [Obliv-C](https://oblivc.org)
3. [unboundsecurity](https://github.com/unboundsecurity/blockchain-crypto-mpc)
