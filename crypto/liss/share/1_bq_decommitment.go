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
	bqForm "github.com/getamis/alice/crypto/binaryquadraticform"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/libs/message/types"
	"github.com/getamis/sirius/log"
)

type bqDecommitmentHandler struct {
	*bqCommitmentHandler

	publicKey        *cl.PublicKey
	shareCommitments [][]map[string]*bqForm.BQuadraticForm
}

func newBqDecommitmentHandler(h *bqCommitmentHandler) (*bqDecommitmentHandler, error) {
	return &bqDecommitmentHandler{
		bqCommitmentHandler: h,
	}, nil
}

func (p *bqDecommitmentHandler) MessageType() types.MessageType {
	return types.MessageType(Type_BqDecommitment)
}

func (p *bqDecommitmentHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *bqDecommitmentHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *bqDecommitmentHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}
	body := msg.GetBqDedemmitment()
	// TODO: Do we need to consider order
	// Check commitment
	var err error
	bqExpM := make([]*bqForm.BQuadraticForm, len(body.ExpM))
	for i, expM := range body.ExpM {
		bqExpM[i], err = expM.ToBQuadraticForm()
		if err != nil {
			logger.Debug("Peer not found")
			return err
		}
	}

	exponentialM := [][]*bqForm.BQuadraticForm{
		p.exponentialM,
		bqExpM,
	}
	decommitMsg := [][]*BqDecommit{
		p.decommitMsg,
		body.Decommitments,
	}
	for i := 0; i < len(decommitMsg[1]); i++ {
		err := decommitMsg[1][i].verify(peer.commitments[i])
		if err != nil {
			logger.Debug("Failed to decommit", "err", err)
			return err
		}
	}

	// Compute all sums
	sumExponential := make([]*bqForm.BQuadraticForm, len(p.exponential))
	for i := 0; i < len(sumExponential); i++ {
		temp, err := decommitMsg[0][i].Bqform.ToBQuadraticForm()
		if err != nil {
			logger.Debug("Failed to ToBQuadraticForm", "err", err)
			return err
		}
		for j := 1; j < len(decommitMsg); j++ {
			tempFrom, err := decommitMsg[j][i].Bqform.ToBQuadraticForm()
			if err != nil {
				logger.Debug("Failed to ToBQuadraticForm", "err", err)
				return err
			}
			temp, err = temp.Composition(tempFrom)
			if err != nil {
				logger.Debug("Failed to Composition", "err", err)
				return err
			}
		}
		sumExponential[i] = temp
	}
	sumExponentialM := make([]*bqForm.BQuadraticForm, p.configsMatrix.GetNumberRow())
	for i := 0; i < len(sumExponentialM); i++ {
		temp := exponentialM[0][i]
		for j := 1; j < len(exponentialM); j++ {
			temp, err = temp.Composition(exponentialM[j][i])
			if err != nil {
				logger.Debug("Failed to Composition", "err", err)
				return err
			}
		}
		sumExponentialM[i] = temp
	}

	// Computing matrix acts on sumExponential vectors.
	computeSumExponentialM := make([]*bqForm.BQuadraticForm, p.configsMatrix.GetNumberRow())
	orgMatrix := p.configsMatrix
	for i := uint64(0); i < orgMatrix.GetNumberRow(); i++ {
		tempRow, err := orgMatrix.GetRow(i)
		if err != nil {
			logger.Debug("Failed to GetRow", "err", err)
			return err
		}
		computeSumExponentialM[i], err = bqForm.LinearCombination(tempRow, sumExponential)
		if err != nil {
			logger.Debug("Failed to LinearCombination", "err", err)
			return err
		}
	}

	// Compare
	for i := 0; i < len(computeSumExponentialM); i++ {
		if !computeSumExponentialM[i].Equal(sumExponentialM[i]) {
			logger.Debug("Failed to verify", "computeSumExponentialM", computeSumExponentialM, "sumExponentialM", sumExponentialM)
			return ErrFailedVerify
		}
	}

	// Set public Key:
	p.publicKey, err = p.clParameter.GeneratePublicKey(sumExponential[0])
	if err != nil {
		logger.Debug("Failed to GeneratePublicKey", "err", err)
		return err
	}

	// Set shareCommit
	p.shareCommitments = p.configs.GetCommitmentOrderBySerialNumber(sumExponentialM)
	return peer.AddMessage(msg)
}

func (p *bqDecommitmentHandler) Finalize(logger log.Logger) (types.Handler, error) {
	return nil, nil
}
