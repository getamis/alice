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
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

const (
	TypeDKG    int = 0
	TypeSigner int = 1
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

// GetFilePath generates the file path from type and peer ID.
func GetFilePath(rType int, id string) string {
	var resultType string
	if rType == TypeDKG {
		resultType = "dkg"
	} else if rType == TypeSigner {
		resultType = "signer"
	}
	return fmt.Sprintf("%s/%s-output.yaml", resultType, id)
}
