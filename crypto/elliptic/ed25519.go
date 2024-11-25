// Copyright © 2022 AMIS Technologies
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

package elliptic

import (
	"crypto/elliptic"
	"math/big"

	ED25519 "github.com/getamis/alice/crypto/elliptic/ed25519prue"

	"github.com/decred/dcrd/dcrec/edwards"
)

var (
	big1         = big.NewInt(1)
	ed25519Curve = &ed25519{
		Curve: edwards.Edwards(),
	}

	BIP32ED25519 = "bip32"
)

type ed25519 struct {
	elliptic.Curve
}

func Ed25519() *ed25519 {
	return ed25519Curve
}

// Warn: does not deal with the original point
func (ed *ed25519) Neg(x, y *big.Int) (*big.Int, *big.Int) {
	negativeX := new(big.Int).Neg(x)
	return negativeX.Mod(negativeX, ed.Params().P), new(big.Int).Set(y)
}

func (ed *ed25519) Type() string {
	return "ed25519"
}

func (ed *ed25519) Slip10SeedList() []byte {
	return []byte("ed25519 seed")
}

func (ed *ed25519) CompressedPublicKey(secret *big.Int, method string) ([]byte, error) {
	if method == BIP32ED25519 {
		pubKey, err := ED25519.PubKeyCompression(secret.Bytes())
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	} else {
		privateKey := ED25519.NewKeyFromSeed(secret.Bytes()[:32])
		return privateKey[32:], nil
	}
}
