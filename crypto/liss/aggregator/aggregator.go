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
	liss "github.com/getamis/alice/crypto/liss"
)

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)

	//ErrFailedVerify is returned if we verify failed
	ErrFailedVerify = errors.New("failed verify")
	//ErrWrongQuantity is returned if the quantity is wrong
	ErrWrongQuantity = errors.New("the quantity is wrong")
	//ErrWrongMessage is returned if the message is wrong
	ErrWrongMessage = errors.New("the message is wrong")
	//ErrTrivialKey is returned if the public key is trivial
	ErrTrivialKey = errors.New("the public key is trivial")
)

type Aggregator struct {
	groups       []*Group
	tssPublicKey *pt.ECPoint
	clPubKey     *cl.PublicKey
	r            *big.Int // signature: r
	m            *big.Int // message
	proofs       []*cl.ConsistencyProofMessage
	c2           *bqForm.BQuadraticForm
}

func NewAggregator(configs liss.GroupConfigs, tssPublicKey *pt.ECPoint, clPubKey *cl.PublicKey, r *big.Int, m *big.Int, proofs []*cl.ConsistencyProofMessage) (*Aggregator, error) {
	if err := verifyProof(clPubKey, r, proofs); err != nil {
		return nil, err
	}
	groups := make([]*Group, len(configs))
	for i, c := range configs {
		groups[i] = &Group{
			GroupConfig: c,
			UserResults: make([]map[string]*bqForm.BQuadraticForm, c.Users),
		}
	}
	agg := &Aggregator{
		groups:       groups,
		tssPublicKey: tssPublicKey,
		clPubKey:     clPubKey,
		r:            r,
		m:            m,
		proofs:       proofs,
	}
	err := agg.computeC2()
	if err != nil {
		return nil, err
	}
	return agg, nil
}

// Check that get all partial signatures are valid
func (agg *Aggregator) computeC2() error {
	// Compute C2:
	c2, err := agg.proofs[0].C2.ToBQuadraticForm()
	if err != nil {
		return err
	}
	for i := 1; i < len(agg.proofs); i++ {
		temp, err := agg.proofs[i].C2.ToBQuadraticForm()
		if err != nil {
			return err
		}
		c2, err = c2.Composition(temp)
		if err != nil {
			return err
		}
	}
	agg.c2 = c2
	return nil
}

func (agg *Aggregator) Add(groupIndex int, userIndex int, partialCiphertext map[string]*bqForm.BQuadraticForm) bool {
	if groupIndex >= len(agg.groups) || groupIndex < 0 {
		return false
	}
	group := agg.groups[groupIndex]
	if userIndex >= group.Users || userIndex < 0 {
		return false
	}
	// failure if we set before
	if group.UserResults[userIndex] != nil {
		return false
	}
	return group.Add(userIndex, partialCiphertext)
}

// IsEnough checks if all gorups collects enough user results
func (agg *Aggregator) IsEnough() bool {
	for _, c := range agg.groups {
		if !c.IsEnough() {
			return false
		}
	}
	return true
}

// TODO: Add signature verifycation
// Get an ECDSA signature (r,s)
func (agg *Aggregator) GetS() (*big.Int, error) {
	// Compose all groups
	c1, err := agg.groups[0].GetComposition()
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(agg.groups); i++ {
		tmp, err := agg.groups[i].GetComposition()
		if err != nil {
			return nil, err
		}
		c1, err = c1.Composition(tmp.Inverse())
		if err != nil {
			return nil, err
		}
	}

	// Get signature
	curveN := agg.tssPublicKey.GetCurve().Params().N
	message, err := agg.c2.Composition(c1.Inverse())
	if err != nil {
		return nil, err
	}
	result := message.GetB()
	result.Div(result, curveN)
	result.ModInverse(result, curveN)
	return result, nil
}

// Check: r = Rx, consistency proof, and R is not trivial.
func verifyProof(clPubKey *cl.PublicKey, r *big.Int, proofMsg []*cl.ConsistencyProofMessage) error {
	var err error
	for i := 0; i < len(proofMsg); i++ {
		err = clPubKey.VerifyConsistencyProof(proofMsg[i])
		if err != nil {
			return err
		}
		R, err := proofMsg[i].R.ToPoint()
		if err != nil {
			return err
		}
		if R.IsIdentity() {
			return ErrFailedVerify
		}
		if r.Cmp(R.GetX()) != 0 {
			return ErrFailedVerify
		}
	}
	return nil
}
