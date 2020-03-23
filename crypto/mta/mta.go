// Copyright © 2020 AMIS Technologies
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

package mta

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
)

var (
	// ErrInconsistentAlphaAndBeta is returned if the number of alpha and beta are inconsistent
	ErrInconsistentAlphaAndBeta = errors.New("inconsistent alpha and beta")

	big0 = big.NewInt(0)
)

type Mta struct {
	filedOrder *big.Int
	homoCrypto homo.Crypto

	k *big.Int
	a *big.Int
}

func NewMta(filedOrder *big.Int, homoCrypto homo.Crypto) (*Mta, error) {
	k, err := utils.RandomInt(filedOrder)
	if err != nil {
		return nil, err
	}
	a, err := utils.RandomInt(filedOrder)
	if err != nil {
		return nil, err
	}
	return &Mta{
		filedOrder: filedOrder,
		homoCrypto: homoCrypto,

		k: k,
		a: a,
	}, nil
}

// OverrideA returns the encrypted k
func (m *Mta) OverrideA(newA *big.Int) (*Mta, error) {
	err := utils.InRange(newA, big0, m.filedOrder)
	if err != nil {
		return nil, err
	}
	return &Mta{
		filedOrder: m.filedOrder,
		homoCrypto: m.homoCrypto,

		k: m.k,
		a: newA,
	}, nil
}

// GetEncK returns the encrypted k
func (m *Mta) GetEncK() ([]byte, error) {
	return m.homoCrypto.Encrypt(m.k.Bytes())
}

// GetAG returns ag
func (m *Mta) GetAG(curve elliptic.Curve) *pt.ECPoint {
	return pt.ScalarBaseMult(curve, m.a)
}

// GetAProof returns Schnorr proof message of a
func (m *Mta) GetAProof(curve elliptic.Curve) (*zkproof.SchnorrProofMessage, error) {
	return zkproof.NewBaseSchorrMessage(curve, m.a)
}

// GetAK returns ak
func (m *Mta) GetAK() *big.Int {
	return new(big.Int).Mul(m.a, m.k)
}

// GetProductWithK returns the k*v
func (m *Mta) GetProductWithK(v *big.Int) *big.Int {
	return new(big.Int).Mul(m.k, v)
}

// Decrypt decrypts the encrypted message
func (m *Mta) Decrypt(c *big.Int) (*big.Int, error) {
	bs, err := m.homoCrypto.Decrypt(c.Bytes())
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(bs), nil
}

// Compute gets the encrypted k with a random beta
// alpha = (E(encMessage) * a) + E(beta), where * is the homomorphic multiply amd + is the homomorphic Addition.
func (m *Mta) Compute(publicKey homo.Pubkey, encMessage []byte) (*big.Int, *big.Int, error) {
	// Verify proof
	err := publicKey.VerifyEnc(encMessage)
	if err != nil {
		return nil, nil, err
	}

	// Generate beta
	betaRange := publicKey.GetMessageRange(m.filedOrder)
	beta, err := utils.RandomInt(betaRange)
	if err != nil {
		return nil, nil, err
	}

	encBeta, err := publicKey.Encrypt(beta.Bytes())
	if err != nil {
		return nil, nil, err
	}

	// (E(encMessage) * a) + E(beta)
	r, err := publicKey.MulConst(encMessage, m.a)
	if err != nil {
		return nil, nil, err
	}
	r, err = publicKey.Add(r, encBeta)
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(r), new(big.Int).Neg(beta), nil
}

func (m *Mta) GetProofWithCheck(curve elliptic.Curve, beta *big.Int) ([]byte, error) {
	return m.homoCrypto.GetMtaProof(curve, beta, m.a)
}

func (m *Mta) VerifyProofWithCheck(proof []byte, curve elliptic.Curve, alpha *big.Int) (*pt.ECPoint, error) {
	return m.homoCrypto.VerifyMtaProof(proof, curve, alpha, m.k)
}

// GetResult returns the result by alphas and betas
func (m *Mta) GetResult(alphas []*big.Int, betas []*big.Int) (*big.Int, error) {
	if len(alphas) != len(betas) {
		return nil, ErrInconsistentAlphaAndBeta
	}
	delta := m.GetAK()
	for i, a := range alphas {
		delta = new(big.Int).Add(delta, a)
		delta = new(big.Int).Add(delta, betas[i])
	}
	return new(big.Int).Mod(delta, m.filedOrder), nil
}
