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

package cl

import (
	"errors"
	"math/big"

	binaryquadraticform "github.com/getamis/alice/crypto/binaryquadraticform"
	"github.com/golang/protobuf/proto"
)

var (
	//ErrInvalidMessage is returned if the message is invalid
	ErrInvalidMessage = errors.New("invalid message")
)

func newBQs(desP *big.Int, data []byte) (*binaryquadraticform.BQuadraticForm, *binaryquadraticform.BQuadraticForm, error) {
	msg := &EncryptedMessage{}
	err := proto.Unmarshal(data, msg)
	if err != nil {
		return nil, nil, err
	}
	return msg.getBQs(desP)
}

func (m *EncryptedMessage) getBQs(desP *big.Int) (*binaryquadraticform.BQuadraticForm, *binaryquadraticform.BQuadraticForm, error) {
	m1, err := m.M1.ToBQuadraticForm()
	if err != nil {
		return nil, nil, err
	}
	if m1.GetDiscriminant().Cmp(desP) != 0 {
		return nil, nil, ErrInvalidMessage
	}
	m2, err := m.M2.ToBQuadraticForm()
	if err != nil {
		return nil, nil, err
	}
	if m2.GetDiscriminant().Cmp(desP) != 0 {
		return nil, nil, ErrInvalidMessage
	}
	if !m1.IsReducedForm() {
		return nil, nil, ErrInvalidMessage
	}
	if !m2.IsReducedForm() {
		return nil, nil, ErrInvalidMessage
	}
	return m1, m2, nil
}

func (m *PubKeyMessage) ToPubkey() (*PublicKey, error) {
	p := new(big.Int).SetBytes(m.P)
	a := new(big.Int).SetBytes(m.A)
	q := new(big.Int).SetBytes(m.Q)
	c := new(big.Int).SetBytes(m.C)
	if p.Cmp(big0) < 1 {
		return nil, ErrInvalidMessage
	}
	if a.Cmp(big0) < 1 {
		return nil, ErrInvalidMessage
	}
	if q.Cmp(big0) < 1 {
		return nil, ErrInvalidMessage
	}
	if c.Cmp(big0) < 1 {
		return nil, ErrInvalidMessage
	}
	g, err := m.G.ToBQuadraticForm()
	if err != nil {
		return nil, err
	}
	f, err := m.F.ToBQuadraticForm()
	if err != nil {
		return nil, err
	}
	h, err := m.H.ToBQuadraticForm()
	if err != nil {
		return nil, err
	}

	// build cache value
	absDiscriminantK := new(big.Int).Mul(p, q)
	pSquare := new(big.Int).Mul(p, p)
	discriminantOrderP := new(big.Int).Mul(absDiscriminantK, pSquare)
	discriminantOrderP = discriminantOrderP.Neg(discriminantOrderP)

	publicKey, err := newPubKey(m.GetProof(), m.D, discriminantOrderP, a, c, p, q, g, f, h)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}
