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

package tss

import (
	"errors"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/sirius/log"
)

var (
	ErrInvalidMsg                = errors.New("invalid message")
	ErrNotReady                  = errors.New("not ready")
	ErrPeerNotFound              = errors.New("peer message not found")
	ErrNotEnoughBKs              = errors.New("not enough Birkhoff coefficient")
	ErrSelfBKNotFound            = errors.New("self Birkhoff coefficient not found")
	ErrInvalidBK                 = errors.New("invalid Birkhoff coefficient")
	ErrInconsistentThreshold     = errors.New("inconsistent threshold")
	ErrInconsistentPeerNumAndBks = errors.New("inconsistent peer num and bks")
	ErrInconsistentPubKey        = errors.New("inconsistent public key")
)

func NewCommitterByPoint(p *pt.ECPoint) (*commitment.HashCommitmenter, error) {
	msg, err := p.ToEcPointMessage()
	if err != nil {
		log.Warn("Failed to convert to an ec point message", "err", err)
		return nil, err
	}

	return commitment.NewProtoHashCommitmenter(msg)
}

func GetPointFromHashCommitment(logger log.Logger, commit *commitment.HashCommitmentMessage, decommit *commitment.HashDecommitmentMessage) (*pt.ECPoint, error) {
	msg := &pt.EcPointMessage{}
	err := commit.DecommitToProto(decommit, msg)
	if err != nil {
		logger.Warn("Failed to decommit message", "err", err)
		return nil, err
	}
	point, err := msg.ToPoint()
	if err != nil {
		logger.Warn("Failed to convert to ec point", "err", err)
		return nil, err
	}
	return point, nil
}

func ValidatePublicKey(logger log.Logger, bks birkhoffinterpolation.BkParameters, sgs []*pt.ECPoint, threshold uint32, pubkey *pt.ECPoint) error {
	fieldOrder := pubkey.GetCurve().Params().N
	scalars, err := bks.ComputeBkCoefficient(threshold, fieldOrder)
	if err != nil {
		logger.Warn("Failed to compute", "err", err)
		return err
	}
	gotPub, err := pt.ComputeLinearCombinationPoint(scalars, sgs)
	if err != nil {
		logger.Warn("Failed to calculate public", "err", err)
		return err
	}
	if !pubkey.Equal(gotPub) {
		logger.Warn("Inconsistent public key", "got", gotPub, "expected", pubkey)
		return ErrInconsistentPubKey
	}
	return nil
}
