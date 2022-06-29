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

package signer

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/types/message"
)

type peer struct {
	*message.Peer

	// initial data
	index int
	bk    *birkhoffinterpolation.BkParameter
	coBk  *big.Int

	// round 1
	D   *ecpointgrouplaw.ECPoint
	E   *ecpointgrouplaw.ECPoint
	Y   *ecpointgrouplaw.ECPoint
	ell *big.Int
	ri  *ecpointgrouplaw.ECPoint

	// round 2
	si *big.Int
}

type peers []*peer

func (p peers) Len() int           { return len(p) }
func (p peers) Less(i, j int) bool { return p[i].bk.GetX().Cmp(p[j].bk.GetX()) < 0 }
func (p peers) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func newPeer(id string, index int, bk *birkhoffinterpolation.BkParameter) *peer {
	return &peer{
		Peer:  message.NewPeer(id),
		index: index,
		bk:    bk,
	}
}
