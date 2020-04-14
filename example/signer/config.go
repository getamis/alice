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
package signer

import (
	"errors"
	"io/ioutil"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/signer"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/alice/example/utils"
	"github.com/getamis/sirius/log"
	"gopkg.in/yaml.v2"
)

var (
	// ErrConversion for big int convestion error
	ErrConversion = errors.New("conversion error")
)

type SignerConfig struct {
	Port    int64                `yaml:"port"`
	Share   string               `yaml:"share"`
	Pubkey  config.Pubkey        `yaml:"pubkey"`
	BKs     map[string]config.BK `yaml:"bks"`
	Message string               `yaml:"msg"`
	Peers   []int64              `yaml:"peers"`
}

type SignerResult struct {
	R string `yaml:"r"`
	S string `yaml:"s"`
}

func readSignerConfigFile(filaPath string) (*SignerConfig, error) {
	c := &SignerConfig{}
	yamlFile, err := ioutil.ReadFile(filaPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func writeSignerResult(id string, result *signer.Result) error {
	signerResult := &SignerResult{
		R: result.R.String(),
		S: result.S.String(),
	}
	err := config.WriteYamlFile(signerResult, utils.GetFilePath(utils.TypeSigner, id))
	if err != nil {
		log.Error("Cannot write YAML file", "err", err)
		return err
	}
	return nil
}

func convertDKGResult(config *SignerConfig) (*dkg.Result, error) {
	// Build public key.
	x, ok := new(big.Int).SetString(config.Pubkey.X, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "x", config.Pubkey.X)
		return nil, ErrConversion
	}
	y, ok := new(big.Int).SetString(config.Pubkey.Y, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "y", config.Pubkey.Y)
		return nil, ErrConversion
	}
	pubkey, err := ecpointgrouplaw.NewECPoint(utils.GetCurve(), x, y)
	if err != nil {
		log.Error("Cannot get public key", "err", err)
		return nil, err
	}

	// Build share.
	share, ok := new(big.Int).SetString(config.Share, 10)
	if !ok {
		log.Error("Cannot convert string to big int", "share", config.Share)
		return nil, ErrConversion
	}

	dkgResult := &dkg.Result{
		PublicKey: pubkey,
		Share:     share,
		Bks:       make(map[string]*birkhoffinterpolation.BkParameter),
	}

	// Build bks.
	for peerID, bk := range config.BKs {
		x, ok := new(big.Int).SetString(bk.X, 10)
		if !ok {
			log.Error("Cannot convert string to big int", "x", bk.X)
			return nil, ErrConversion
		}
		dkgResult.Bks[peerID] = birkhoffinterpolation.NewBkParameter(x, bk.Rank)
	}

	return dkgResult, nil
}
