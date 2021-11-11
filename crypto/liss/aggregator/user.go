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

package aggregator

import (
	"errors"
	"math/big"

	bqForm "github.com/getamis/alice/crypto/binaryquadraticform"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/liss/share"
)

var (
	//ErrMessageNotConsistency is returned if the messages are not consistency
	ErrMessageNotConsistency = errors.New("the messages are not consistency")
)

type User struct {
	tssPublicKey *pt.ECPoint
	clPubKey     *cl.PublicKey
	r            *big.Int // signature: r
	m            *big.Int // signature: message
	proofs       []*cl.ConsistencyProofMessage
	c1           *bqForm.BQuadraticForm
	shares       *share.UserResult
}

// If you have the following data, then you can use the following constructor
// shares = dealer's share + server's share
func NewUser(tssPublicKey *pt.ECPoint, clPubKey *cl.PublicKey, r *big.Int, m *big.Int, proofs []*cl.ConsistencyProofMessage, shares *share.UserResult) (*User, error) {
	if err := verifyProof(clPubKey, r, proofs); err != nil {
		return nil, err
	}
	u := &User{
		tssPublicKey: tssPublicKey,
		clPubKey:     clPubKey,
		m:            m,
		r:            r,
		proofs:       proofs,
		shares:       shares,
	}
	err := u.computeC1()
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (u *User) Approve() (map[string]*bqForm.BQuadraticForm, error) {
	result := make(map[string]*bqForm.BQuadraticForm)
	var err error
	c := bqForm.NewCacheExp(u.c1)
	for k, v := range u.shares.Shares {
		result[k], err = c.Exp(v.Share)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (u *User) computeC1() error {
	// Compute C2:
	c1, err := u.proofs[0].C1.ToBQuadraticForm()
	if err != nil {
		return err
	}
	for i := 1; i < len(u.proofs); i++ {
		temp, err := u.proofs[i].C1.ToBQuadraticForm()
		if err != nil {
			return err
		}
		c1, err = c1.Composition(temp)
		if err != nil {
			return err
		}
	}
	u.c1 = c1
	return nil
}
