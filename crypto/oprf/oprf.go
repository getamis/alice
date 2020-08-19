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

package oprf

import (
	"errors"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/oprf/hasher"
	"github.com/getamis/alice/crypto/utils"
)

var (
	// big1 is big int 1
	big1 = big.NewInt(1)

	// TODO: always use secp256k1 hasher for now
	secp256k1Hasher = hasher.NewSECP256k1()
	fieldOrder      = secp256k1Hasher.GetN()

	maxRetry = 100

	// ErrZero is returned if the value is zero
	ErrZero = errors.New("zero")
	// ErrIdentityPoint is returned if point is the identity point
	ErrIdentityPoint = errors.New("identity point")
)

type Requester struct {
	pw         []byte
	hashPW     *pt.ECPoint
	hashPWMsg  *pt.EcPointMessage
	r          *big.Int
	alpha      *pt.ECPoint
	requestMsg *OprfRequestMessage
}

type Responser struct {
	k *big.Int
}

// DH-OPRF: ref: https://tools.ietf.org/id/draft-krawczyk-cfrg-opaque-03.html
/*  U(Requester) with input pw and S(Responser) with input k:
U: choose random r in [1,...,q-1], send alpha = r*H'(pw) to S. Here q is the order of a field.
S: upon receiving a value alpha, check alpha != 0 and respond with beta=alpha^k.
U: upon receiving values beta, check beta !=0 and set the PRF output to H(pw, H'(pw), beta/r).
*/
func NewRequester(pw []byte) (*Requester, error) {
	hashPW, r, maskPWPoint, err := generateMaskPoint(pw)
	if err != nil {
		return nil, err
	}
	hashPWMsg, err := hashPW.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	msg, err := maskPWPoint.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	return &Requester{
		pw:        pw,
		hashPW:    hashPW,
		hashPWMsg: hashPWMsg,
		r:         r,
		alpha:     maskPWPoint,
		requestMsg: &OprfRequestMessage{
			Alpha: msg,
		},
	}, nil
}

func (r *Requester) GetRequestMessage() *OprfRequestMessage {
	return r.requestMsg
}

func (r *Requester) Compute(msg *OprfResponseMessage) (*big.Int, error) {
	beta, err := msg.Beta.ToPoint()
	if err != nil {
		return nil, err
	}
	if beta.IsIdentity() {
		return nil, ErrIdentityPoint
	}

	// Get beta/r
	fieldOrder := beta.GetCurve().Params().N
	inverseMaskValue := new(big.Int).ModInverse(r.r, fieldOrder)
	point := beta.ScalarMult(inverseMaskValue)
	pointMsg, err := point.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	return utils.HashProtosToInt(r.pw, r.hashPWMsg, pointMsg)
}

func generateMaskPoint(pw []byte) (*pt.ECPoint, *big.Int, *pt.ECPoint, error) {
	hashPW, err := secp256k1Hasher.Hash(pw)
	if err != nil {
		return nil, nil, nil, err
	}
	r, err := utils.RandomPositiveInt(fieldOrder)
	if err != nil {
		return nil, nil, nil, err
	}
	// compute r*H'(x)
	maskPWPoint := hashPW.ScalarMult(r)
	return hashPW, r, maskPWPoint, nil
}

func NewResponser() (*Responser, error) {
	k, err := utils.RandomPositiveInt(fieldOrder)
	if err != nil {
		return nil, err
	}
	return NewResponserWithK(k)
}

func NewResponserWithK(k *big.Int) (*Responser, error) {
	err := utils.InRange(k, big1, fieldOrder)
	if err != nil {
		return nil, err
	}
	return &Responser{
		k: k,
	}, nil
}

func (r *Responser) GetK() *big.Int {
	return new(big.Int).Set(r.k)
}
func (r *Responser) Handle(msg *OprfRequestMessage) (*OprfResponseMessage, error) {
	alpha, err := msg.Alpha.ToPoint()
	if err != nil {
		return nil, err
	}

	if alpha.IsIdentity() {
		return nil, ErrIdentityPoint
	}
	// beta = k*alpha
	result := alpha.ScalarMult(r.k)
	response, err := result.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	return &OprfResponseMessage{
		Beta: response,
	}, nil
}

func ComputeShare(k *big.Int, password []byte, hashCurve hasher.Hasher) (*big.Int, error) {
	pwHash, err := hashCurve.Hash(password)
	if err != nil {
		return nil, err
	}
	pwMessage, err := pwHash.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	productPoint := pwHash.ScalarMult(k)
	productMessage, err := productPoint.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	return utils.HashProtosToInt(password, pwMessage, productMessage)
}
