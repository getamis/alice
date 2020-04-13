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
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/signer"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/sirius/log"
)

const (
	typeDKG    int = 0
	typeSigner int = 1
)

var (
	// ErrConvertion for big int convertion error
	ErrConvertion = errors.New("convertion error")
)

// WriteDKGResult writes the peer's dkg result.
func WriteDKGResult(id string, result *dkg.Result) error {
	dkgResult := &config.DKGResult{
		Share: result.Share.String(),
		Pubkey: config.Pubkey{
			X: result.PublicKey.GetX().String(),
			Y: result.PublicKey.GetY().String(),
		},
		BKs: make(map[string]config.BK),
	}
	for peerID, bk := range result.Bks {
		dkgResult.BKs[peerID] = config.BK{
			X:    bk.GetX().String(),
			Rank: bk.GetRank(),
		}
	}
	err := config.WriteYamlFile(dkgResult, GetFilePath(typeDKG, id))
	if err != nil {
		log.Error("Cannot write YAML file", "err", err)
		return err
	}
	return nil
}

// ReadDKGResult reads the peer's signer result.
func ReadDKGResult(id string) (*dkg.Result, error) {
	c, err := config.ReadDKGResultFile(GetFilePath(typeDKG, id))
	if err != nil {
		log.Error("Cannot read YAML file", "err", err)
		return nil, err
	}

	// Build public key.
	x, ok := new(big.Int).SetString(c.Pubkey.X, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "x", c.Pubkey.X)
		return nil, ErrConvertion
	}
	y, ok := new(big.Int).SetString(c.Pubkey.Y, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "y", c.Pubkey.Y)
		return nil, ErrConvertion
	}
	pubkey, err := ecpointgrouplaw.NewECPoint(GetCurve(), x, y)
	if err != nil {
		log.Error("Cannot get public key", "err", err)
		return nil, err
	}

	// Build share.
	share, ok := new(big.Int).SetString(c.Share, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "share", c.Share)
		return nil, ErrConvertion
	}

	dkgResult := &dkg.Result{
		PublicKey: pubkey,
		Share:     share,
		Bks:       make(map[string]*birkhoffinterpolation.BkParameter),
	}

	// Build bks.
	for peerID, bk := range c.BKs {
		x, ok := new(big.Int).SetString(bk.X, 10)
		if !ok {
			log.Error("Cannot convert string to big int", "x", c.Pubkey.X)
			return nil, ErrConvertion
		}
		dkgResult.Bks[peerID] = birkhoffinterpolation.NewBkParameter(x, bk.Rank)
	}

	return dkgResult, nil
}

// WriteSignerResult writes the peer's signer result.
func WriteSignerResult(id string, result *signer.Result) error {
	signerResult := &config.SignerResult{
		R: result.R.String(),
		S: result.S.String(),
	}
	err := config.WriteYamlFile(signerResult, GetFilePath(typeSigner, id))
	if err != nil {
		log.Error("Cannot write YAML file", "err", err)
		return err
	}
	return nil
}

// GetFilePath get the result file path according to its type and peer ID.
func GetFilePath(rType int, id string) string {
	var resultType string
	if rType == typeDKG {
		resultType = "dkg"
	} else if rType == typeSigner {
		resultType = "signer"
	}
	return fmt.Sprintf("result_%s_%s.yaml", resultType, id)
}

// GetPeerIDFromPort gets peer ID from port.
func GetPeerIDFromPort(port int64) string {
	// For convenience, we set peer ID as "id-" + port
	return fmt.Sprintf("id-%d", port)
}

// GetCurve returns the curve we used in this example.
// For simplicity, we use S256 curve.
func GetCurve() *btcec.KoblitzCurve {
	return btcec.S256()
}
