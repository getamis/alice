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

package sign

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/cggmp"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/internal/message"
)

type peer struct {
	*message.Peer

	// init data
	ssidWithBk    []byte
	bk            *birkhoffinterpolation.BkParameter
	bkcoefficient *big.Int
	para          *paillier.PederssenOpenParameter
	partialPubKey *pt.ECPoint
	allY          *pt.ECPoint

	round1Data *round1Data
	round2Data *round2Data
	round3Data *round3Data
	round4Data *round4Data
}

func newPeer(id string, ssid []byte, bk *birkhoffinterpolation.BkParameter, bkcoefficient *big.Int, para *paillier.PederssenOpenParameter, partialPubKey *pt.ECPoint, allY *pt.ECPoint) *peer {
	ssidWithBk := cggmp.ComputeZKSsid(ssid, bk)
	return &peer{
		Peer:          message.NewPeer(id),
		ssidWithBk:    ssidWithBk,
		bk:            bk,
		bkcoefficient: bkcoefficient,
		para:          para,
		partialPubKey: partialPubKey,
		allY:          allY,
	}
}
