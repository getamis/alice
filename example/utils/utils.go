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
package utils

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/aisuosuo/alice/crypto/birkhoffinterpolation"
	"github.com/aisuosuo/alice/crypto/ecpointgrouplaw"
	"github.com/aisuosuo/alice/crypto/tss/dkg"
	"github.com/aisuosuo/alice/example/config"
	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/sirius/log"
)

var (
	// ErrConversion for big int conversion error
	ErrConversion = errors.New("conversion error")
)

// GetPeerIDFromPort gets peer ID from port.
func GetPeerIDFromPort(port int64) string {
	// For convenience, we set peer ID as "id-" + port
	return fmt.Sprintf("id-%d", port)
}

// GetCurve returns the curve we used in this example.
func GetCurve() elliptic.Curve {
	// For simplicity, we use S256 curve.
	return btcec.S256()
}

// ConvertDKGResult converts DKG result from config.
func ConvertDKGResult(cfgPubkey config.Pubkey, cfgShare string, cfgBKs map[string]config.BK) (*dkg.Result, error) {
	// Build public key.
	x, ok := new(big.Int).SetString(cfgPubkey.X, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "x", cfgPubkey.X)
		return nil, ErrConversion
	}
	y, ok := new(big.Int).SetString(cfgPubkey.Y, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "y", cfgPubkey.Y)
		return nil, ErrConversion
	}
	pubkey, err := ecpointgrouplaw.NewECPoint(GetCurve(), x, y)
	if err != nil {
		log.Error("Cannot get public key", "err", err)
		return nil, err
	}

	// Build share.
	share, ok := new(big.Int).SetString(cfgShare, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "share", share)
		return nil, ErrConversion
	}

	dkgResult := &dkg.Result{
		PublicKey: pubkey,
		Share:     share,
		Bks:       make(map[string]*birkhoffinterpolation.BkParameter),
	}

	// Build bks.
	for peerID, bk := range cfgBKs {
		x, ok := new(big.Int).SetString(bk.X, 10)
		if !ok {
			log.Error("Cannot convert string to big int", "x", bk.X)
			return nil, ErrConversion
		}
		dkgResult.Bks[peerID] = birkhoffinterpolation.NewBkParameter(x, bk.Rank)
	}

	return dkgResult, nil
}
