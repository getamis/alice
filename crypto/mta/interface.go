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
	"math/big"

	"github.com/getamis/alice/crypto/elliptic"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/zkproof"
)

//go:generate mockery -name Mta
type Mta interface {
	OverrideA(newA *big.Int) (Mta, error)
	GetEncK() []byte
	GetAG(curve elliptic.Curve) *pt.ECPoint
	GetAProof(curve elliptic.Curve) (*zkproof.SchnorrProofMessage, error)
	GetAK() *big.Int
	GetProductWithK(v *big.Int) *big.Int
	Decrypt(c *big.Int) (*big.Int, error)
	Compute(publicKey homo.Pubkey, encMessage []byte) (*big.Int, *big.Int, error)
	GetProofWithCheck(curve elliptic.Curve, beta *big.Int) ([]byte, error)
	VerifyProofWithCheck(proof []byte, curve elliptic.Curve, alpha *big.Int) (*pt.ECPoint, error)
	GetResult(alphas []*big.Int, betas []*big.Int) (*big.Int, error)
}
