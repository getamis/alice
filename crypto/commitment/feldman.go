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
	"errors"
	"math/big"

	bkhoff "github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/polynomial"
)

var (
	// ErrDifferentLength is returned if the two slices has different lengths.
	ErrDifferentLength = errors.New("different lengths of slices")
	// ErrFailedVerify is returned if it's failed to verify
	ErrFailedVerify = errors.New("failed to verify")
)

type FeldmanCommitmenter struct {
	curve   elliptic.Curve
	secrets *polynomial.Polynomial

	commitMessage *PointCommitmentMessage
}

// NewFeldmanCommitmenter creates a new FeldmanCommitmenter.
func NewFeldmanCommitmenter(curve elliptic.Curve, secrets *polynomial.Polynomial) (*FeldmanCommitmenter, error) {
	commitMessage, err := buildFeldmanCommitMessage(curve, secrets)
	if err != nil {
		return nil, err
	}

	return &FeldmanCommitmenter{
		curve:         curve,
		secrets:       secrets,
		commitMessage: commitMessage,
	}, nil
}

func buildFeldmanCommitMessage(curve elliptic.Curve, secrets *polynomial.Polynomial) (*PointCommitmentMessage, error) {
	lens := secrets.Len()
	msg := &PointCommitmentMessage{
		Points: make([]*ecpointgrouplaw.EcPointMessage, lens),
	}
	for i := 0; i < lens; i++ {
		pt := ecpointgrouplaw.ScalarBaseMult(curve, secrets.Get(i))
		var err error
		msg.Points[i], err = pt.ToEcPointMessage()
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// GetVerifyMessage returns the message for verification. In Feldman commitment, the verification message
// only contains the secret.
func (fc *FeldmanCommitmenter) GetVerifyMessage(bk *bkhoff.BkParameter) *FeldmanVerifyMessage {
	x := bk.GetX()
	times := bk.GetRank()
	secrets := fc.secrets.Differentiate(times)
	return &FeldmanVerifyMessage{
		Evaluation: secrets.Evaluate(x).Bytes(),
	}
}

// GetCommitmentMessage returns the commitment message.
func (fc *FeldmanCommitmenter) GetCommitmentMessage() *PointCommitmentMessage {
	return fc.commitMessage
}

// Verify verifies the commitment.
func (vMsg *FeldmanVerifyMessage) Verify(cMsg *PointCommitmentMessage, bk *bkhoff.BkParameter, degree uint32) error {
	curve, err := cMsg.getEllipticCurve(degree)
	if err != nil {
		return err
	}
	pts, err := cMsg.EcPoints()
	if err != nil {
		return err
	}
	return vMsg.VerifyByPoints(curve, pts, bk, degree)
}

func (vMsg *FeldmanVerifyMessage) VerifyByPoints(curve elliptic.Curve, pts []*pt.ECPoint, bk *bkhoff.BkParameter, degree uint32) error {
	fieldOrder := curve.Params().N
	expectPoint := ecpointgrouplaw.ScalarBaseMult(curve, new(big.Int).SetBytes(vMsg.Evaluation))
	scalars := bk.GetLinearEquationCoefficient(fieldOrder, degree)
	tempResult, err := pt.ComputeLinearCombinationPoint(scalars, pts)
	if err != nil {
		return err
	}
	if !tempResult.Equal(expectPoint) {
		return ErrFailedVerify
	}
	return nil
}

func (cMsg *PointCommitmentMessage) getEllipticCurve(degree uint32) (elliptic.Curve, error) {
	if len(cMsg.Points) != int(degree+1) {
		return nil, ErrDifferentLength
	}
	return cMsg.Points[0].Curve.GetEllipticCurve()
}
