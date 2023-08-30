// Copyright © 2020 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/getamis/sirius/log"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	reshare "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	zkPaillier "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/example/config"
)

var (
	// ErrConversion for big int conversion error
	ErrConversion = errors.New("conversion error")
)

// GetCurve returns the curve we used in this example.
func GetCurve() elliptic.Curve {
	// For simplicity, we use S256 curve.
	return elliptic.Secp256k1()
}

// ConvertDKGResult converts DKG result from config.
func ConvertDKGResult(cfgPubkey config.Pubkey, cfgShare string, cfgBKs map[string]config.BK, rid string) (*dkg.Result, error) {
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

	rawRid, err := hex.DecodeString(rid)
	if err != nil {
		log.Error("Cannot get rid", "err", err)
		return nil, err
	}

	dkgResult := &dkg.Result{
		PublicKey: pubkey,
		Share:     share,
		Bks:       make(map[string]*birkhoffinterpolation.BkParameter),
		Rid:       rawRid,
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

// ConvertReshareResult converts the reshare result from config.
func ConvertReshareResult(cfgShare string, paillierKey config.PaillierKey, ySecret string, partialPubKeys map[string]config.Pubkey, y map[string]config.ECPoint, pedParams map[string]config.PederssenOpenParameter) (*reshare.Result, error) {
	r := &reshare.Result{
		PartialPubKey: make(map[string]*ecpointgrouplaw.ECPoint),
		Y:             make(map[string]*ecpointgrouplaw.ECPoint),
		PedParameter:  make(map[string]*zkPaillier.PederssenOpenParameter),
	}

	// Build share.
	share, ok := new(big.Int).SetString(cfgShare, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "share", share)
		return nil, ErrConversion
	}

	r.Share = share

	ys, ok := new(big.Int).SetString(ySecret, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "share", share)
		return nil, ErrConversion
	}

	r.YSecret = ys

	p, ok := new(big.Int).SetString(paillierKey.P, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "p", paillierKey.P)
		return nil, ErrConversion
	}
	q, ok := new(big.Int).SetString(paillierKey.Q, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "q", paillierKey.Q)
		return nil, ErrConversion
	}

	var err error

	r.PaillierKey, err = paillier.NewPaillierWithGivenPrimes(p, q)
	if err != nil {
		log.Error("Cannot NewPaillierWithGivenPrimes from P and Q", "err", err)
		return nil, err
	}

	for peerId, pub := range partialPubKeys {
		p, err := convertECPoint(pub.X, pub.Y)
		if err != nil {
			log.Error("Cannot convert EC point", "err", err)
			return nil, err
		}

		r.PartialPubKey[peerId] = p
	}

	for peerId, yy := range y {
		p, err := convertECPoint(yy.X, yy.Y)
		if err != nil {
			log.Error("Cannot convert EC point", "err", err)
			return nil, err
		}

		r.Y[peerId] = p
	}

	for peerId, pp := range pedParams {
		n, ok := new(big.Int).SetString(pp.N, 10)
		if !ok {
			log.Error("Cannot convert string to big int", "n", pp.N)
			return nil, ErrConversion
		}
		s, ok := new(big.Int).SetString(pp.S, 10)
		if !ok {
			log.Error("Cannot convert string to big int", "s", pp.S)
			return nil, ErrConversion
		}
		t, ok := new(big.Int).SetString(pp.T, 10)
		if !ok {
			log.Error("Cannot convert string to big int", "t", pp.T)
			return nil, ErrConversion
		}

		r.PedParameter[peerId] = zkPaillier.NewPedersenOpenParameter(n, s, t)
	}

	return r, nil
}

func convertECPoint(xx, yy string) (*ecpointgrouplaw.ECPoint, error) {
	// Build public key.
	x, ok := new(big.Int).SetString(xx, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "x", xx)
		return nil, ErrConversion
	}
	y, ok := new(big.Int).SetString(yy, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "y", yy)
		return nil, ErrConversion
	}
	return ecpointgrouplaw.NewECPoint(GetCurve(), x, y)
}
