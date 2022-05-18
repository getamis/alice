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

package homo

import (
	"math/big"

	"github.com/getamis/alice/crypto/elliptic"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
)

//go:generate mockery -name Pubkey
type Pubkey interface {
	GetMessageRange(fieldOrder *big.Int) *big.Int
	Encrypt(m []byte) ([]byte, error)
	Add(c1 []byte, c2 []byte) ([]byte, error)
	MulConst(c []byte, scalar *big.Int) ([]byte, error)
	VerifyEnc([]byte) error
	ToPubKeyBytes() []byte
}

//go:generate mockery -name Crypto
type Crypto interface {
	Pubkey
	Decrypt(c []byte) ([]byte, error)
	GetMtaProof(curve elliptic.Curve, beta *big.Int, a *big.Int) ([]byte, error)
	VerifyMtaProof(msg []byte, curve elliptic.Curve, alpha *big.Int, k *big.Int) (*pt.ECPoint, error)
	GetPubKey() Pubkey
	NewPubKeyFromBytes([]byte) (Pubkey, error)
}
