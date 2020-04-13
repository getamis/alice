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
	"fmt"

	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/sirius/log"
)

const (
	typeDKG int = 0
)

func WriteDKGResult(id string, result *dkg.Result) error {
	dkgResult := &config.DKGResult{
		Share: result.Share.String(),
		Pubkey: config.Pubkey{
			X: result.PublicKey.GetX().String(),
			Y: result.PublicKey.GetY().String(),
		},
		BKs: make(map[string]string),
	}
	for peerID, bk := range result.Bks {
		dkgResult.BKs[peerID] = bk.GetX().String()
	}
	err := config.WriteYamlFile(dkgResult, GetFilePath(typeDKG, id))
	if err != nil {
		log.Error("Cannot write YAML file", "err", err)
		return err
	}
	return nil
}

func GetFilePath(rType int, id string) string {
	var resultType string
	if rType == typeDKG {
		resultType = "dkg"
	}
	return fmt.Sprintf("result_%s_%s.yaml", resultType, id)
}

// GetPeerIDFromPort gets peer ID from port.
func GetPeerIDFromPort(port int64) string {
	// For convenience, we set peer ID as "id-" + port
	return fmt.Sprintf("id-%d", port)
}
