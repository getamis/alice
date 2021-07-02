// Copyright © 2021 AMIS Technologies
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

package share

import (
	"errors"
	"math/big"

	bqForm "github.com/getamis/alice/crypto/binaryquadraticform"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/liss"
)

var (
	ErrNotEnoughKeys = errors.New("not enough keys")
)

type UserResult struct {
	PublicKey *cl.PublicKey
	// Per group, per user
	Shares UserShareMap
}

type UserShareMap map[string]*UserShare

func (u UserShareMap) Has(key string) bool {
	_, ok := u[key]
	return ok
}

func (u UserShareMap) Len() int {
	return len(u)
}

type UserShare struct {
	Bq    *bqForm.BQuadraticForm
	Share *big.Int
}

type Result struct {
	PublicKey *cl.PublicKey
	// Per group, per user
	Users [][]map[string]*UserShare
}

func (m *Result) GetUserResult(groupIndex int, userIndex int) *UserResult {
	return &UserResult{
		PublicKey: m.PublicKey,
		Shares:    m.Users[groupIndex][userIndex],
	}
}

// ComineShares combines shares for users
func ComineShares(config *liss.GroupConfig, userIndex int, shares []*UserResult) (*UserResult, error) {
	// Ensure all keys exist
	for _, s := range shares {
		if !config.CheckKeys(userIndex, s.Shares) {
			return nil, ErrNotEnoughKeys
		}
	}

	// Check public key consistent
	pubKey, err := shares[0].PublicKey.ToPubKeyMessage().ToPubkeyWithoutProof()
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(shares); i++ {
		otherPub, err := shares[i].PublicKey.ToPubKeyMessage().ToPubkeyWithoutProof()
		if err != nil {
			return nil, err
		}
		if !pubKey.EqualWithoutProof(otherPub) {
			return nil, ErrFailedVerify
		}
	}

	// Compose shares
	share := make(map[string]*UserShare)
	g := shares[0].PublicKey.GetG()
	for k, v := range shares[0].Shares {
		s := new(big.Int).Set(v.Share)
		for i := 1; i < len(shares); i++ {
			if !v.Bq.Equal(shares[i].Shares[k].Bq) {
				return nil, ErrFailedVerify
			}
			s.Add(s, shares[i].Shares[k].Share)
		}
		bq, err := g.Exp(s)
		if err != nil {
			return nil, err
		}
		if !bq.Equal(v.Bq) {
			return nil, ErrFailedVerify
		}
		share[k] = &UserShare{
			Bq:    v.Bq,
			Share: s,
		}
	}
	return &UserResult{
		PublicKey: shares[0].PublicKey,
		Shares:    share,
	}, nil
}
