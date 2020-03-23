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

package commitment

import (
	"math/big"

	bkhoff "github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
)

type PedersenCommitmenter struct {
	secrets *polynomial.Polynomial
	salts   *polynomial.Polynomial

	commitMessage *PointCommitmentMessage
}

// NewPedersenCommitmenter creates a new PedersenCommitmenter.
func NewPedersenCommitmenter(threshold uint32, hiddingPoint *pt.ECPoint, secrets *polynomial.Polynomial, salts *polynomial.Polynomial) (*PedersenCommitmenter, error) {
	commitMessage, err := buildPedersenCommitMessage(hiddingPoint, secrets, salts)
	if err != nil {
		return nil, err
	}

	return &PedersenCommitmenter{
		secrets:       secrets,
		salts:         salts,
		commitMessage: commitMessage,
	}, nil
}

/*
   Given two values secret and salt, Pedersen commitment is defined by secret*G + salt*H,
   where H is the hidding point which is determined by Distributed Pedersen Hidding Point Generation and G is the base point of the hidding point.
*/
func computePoint(hiddingPoint *pt.ECPoint, secret *big.Int, salt *big.Int) (*pt.ECPoint, error) {
	curve := hiddingPoint.GetCurve()
	tempPoint := pt.ScalarBaseMult(curve, secret)
	result := hiddingPoint.ScalarMult(salt)
	return tempPoint.Add(result)
}

func buildPedersenCommitMessage(hiddingPoint *pt.ECPoint, secrets *polynomial.Polynomial, salts *polynomial.Polynomial) (*PointCommitmentMessage, error) {
	lens := secrets.Len()
	if lens != salts.Len() {
		return nil, ErrDifferentLength
	}
	msg := &PointCommitmentMessage{
		Points: make([]*pt.EcPointMessage, lens),
	}
	for i := 0; i < lens; i++ {
		pt, err := computePoint(hiddingPoint, secrets.Get(i), salts.Get(i))
		if err != nil {
			return nil, err
		}
		msg.Points[i], err = pt.ToEcPointMessage()
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// GetVerifyMessage returns the message for verification. In Pedersen commitment, the verification message
// contains the secret and salt.
func (pc *PedersenCommitmenter) GetVerifyMessage(bk *bkhoff.BkParameter) *PedersenVerifyMessage {
	x := bk.GetX()
	times := bk.GetRank()
	secrets := pc.secrets.Differentiate(times)
	salts := pc.salts.Differentiate(times)
	return &PedersenVerifyMessage{
		Evaluation: secrets.Evaluate(x).Bytes(),
		Salt:       salts.Evaluate(x).Bytes(),
	}
}

// GetCommitmentMessage returns the commitment message.
func (pc *PedersenCommitmenter) GetCommitmentMessage() *PointCommitmentMessage {
	return pc.commitMessage
}

// Verify verifies the commitment.
// In DKG, other people denoted by Pj will send the corresponding share f^(ri)(xi), g^(ri)(xi) to the participant Pi
// who has the x-Coord xi, the rank ri, secret polynomial f(x) and salt polynomial g(x).
// Then participant Pi can use Pj's pointCommitment to verify the correctness.
// Let the secret polynomial f(x) = a0+a1*x+...+an*x^n and the salt polynomial g(x) = b0+b1*x+...+bn*x^n and Ci := ai*G + bi*H.
// f^(ri)(xi)*g^(ri)(xi) = sum_i (x^i)^(ri)*Ci, where (x^i)^(ri) is the monomial polynomial of degree i and differentiate x^i ri times.
func (vMsg *PedersenVerifyMessage) Verify(cMsg *PointCommitmentMessage, hiddingPoint *pt.ECPoint, bk *bkhoff.BkParameter, degree uint32) error {
	curve, err := cMsg.getEllipticCurve(degree)
	if err != nil {
		return err
	}
	expectPoint, err := computePoint(hiddingPoint, new(big.Int).SetBytes(vMsg.Evaluation), new(big.Int).SetBytes(vMsg.Salt))
	if err != nil {
		return err
	}
	pts, err := cMsg.EcPoints()
	if err != nil {
		return err
	}
	scalars := bk.GetLinearEquationCoefficient(curve.Params().N, degree)
	tempResult, err := pt.ComputeLinearCombinationPoint(scalars, pts)
	if err != nil {
		return err
	}
	if !tempResult.Equal(expectPoint) {
		return ErrFailedVerify
	}
	return nil
}
