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

package paillier

import (
	"math/big"

	"github.com/getamis/alice/crypto/utils"
	zkPaillier "github.com/getamis/alice/crypto/zkproof/paillier"
)

type PederssenParameter struct {
	p      *big.Int
	q      *big.Int
	eulern *big.Int
	lambda *big.Int

	PedersenOpenParameter *zkPaillier.PederssenOpenParameter
}

// By paillier
func (paillier *Paillier) NewPedersenParameterByPaillier() (*PederssenParameter, error) {
	eulern, err := utils.EulerFunction([]*big.Int{paillier.privateKey.p, paillier.privateKey.q})
	n := paillier.publicKey.n
	if err != nil {
		return nil, err
	}
	lambda, err := utils.RandomInt(eulern)
	if err != nil {
		return nil, err
	}
	tau, err := utils.RandomInt(n)
	if err != nil {
		return nil, err
	}
	t := new(big.Int).Exp(tau, big2, n)
	s := new(big.Int).Exp(t, lambda, n)
	return &PederssenParameter{
		p:                     paillier.privateKey.p,
		q:                     paillier.privateKey.q,
		eulern:                eulern,
		lambda:                lambda,
		PedersenOpenParameter: zkPaillier.NewPedersenOpenParameter(n, s, t),
	}, nil
}

func (ped *PederssenParameter) Getlambda() *big.Int {
	return ped.lambda
}

func NewPedersenOpenParameter(n, s, t *big.Int) (*zkPaillier.PederssenOpenParameter, error) {
	if !utils.IsRelativePrime(s, n) {
		return nil, ErrInvalidInput
	}
	if !utils.IsRelativePrime(t, n) {
		return nil, ErrInvalidInput
	}
	if n.BitLen() < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}
	return zkPaillier.NewPedersenOpenParameter(n, s, t), nil
}

func (ped *PederssenParameter) GetP() *big.Int {
	return ped.p
}

func (ped *PederssenParameter) GetQ() *big.Int {
	return ped.q
}

func (ped *PederssenParameter) GetEulerValue() *big.Int {
	return ped.eulern
}

func ToPaillierPubKeyWithSpecialG(ped *zkPaillier.PederssenOpenParameter) *publicKey {
	// special g = 1+ n (ref. definition 2.2 in cggmp)
	n := ped.GetN()
	return &publicKey{
		n:       n,
		g:       new(big.Int).Add(big1, n),
		nSquare: new(big.Int).Mul(n, n),
	}
}

func ToPaillierPubKeyWithSpecialGFromMsg(ssidInfo []byte, msg *zkPaillier.RingPederssenParameterMessage) (*publicKey, error) {
	n := new(big.Int).SetBytes(msg.N)
	if n.BitLen() < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}
	err := msg.Verify(ssidInfo)
	if err != nil {
		return nil, err
	}
	// special g = 1+ n (ref. definition 2.2 in cggmp)
	return &publicKey{
		n:       n,
		g:       new(big.Int).Add(big1, n),
		nSquare: new(big.Int).Mul(n, n),
	}, nil
}
