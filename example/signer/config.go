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
	"encoding/hex"
	"fmt"
	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	"io/ioutil"
	"math/big"

	EDSigner "github.com/getamis/alice/crypto/tss/eddsa/frost/signer"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/sirius/log"
	"gopkg.in/yaml.v2"
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

func writeEDSignerResult(id string, result *EDSigner.Result, sigBytes *[]byte) error {
	test1 := ecpointEncoding(result.R)
	test2 := *test1
	r := new(big.Int).SetBytes(utils.ReverseByte(test2[:]))
	sig := edwards.NewSignature(r, result.S)
	*sigBytes = sig.Serialize()

	log.Info("sign result","",hex.EncodeToString(*sigBytes))
	err := config.WriteYamlFile(hex.EncodeToString(*sigBytes), getFilePath(id))
	if err != nil {
		log.Error("Cannot write YAML file", "err", err)
		return err
	}
	return nil
}

func ecpointEncoding(pt *ecpointgrouplaw.ECPoint) *[32]byte {
	var result, X, Y [32]byte
	var x, y edwards25519.FieldElement
	if pt.Equal(ecpointgrouplaw.NewIdentity(pt.GetCurve())) {
		// TODO: We need to check this
		Y[0] = 1
	} else {
		tempX := pt.GetX().Bytes()
		tempY := pt.GetY().Bytes()

		for i := 0; i < len(tempX); i++ {
			index := len(tempX) - 1 - i
			X[index] = tempX[i]
			Y[index] = tempY[i]
		}
	}
	edwards25519.FeFromBytes(&x, &X)
	edwards25519.FeFromBytes(&y, &Y)
	edwards25519.FeToBytes(&result, &y)
	result[31] ^= edwards25519.FeIsNegative(&x) << 7
	return &result
}

func getFilePath(id string) string {
	return fmt.Sprintf("signer/%s-output.yaml", id)
}
