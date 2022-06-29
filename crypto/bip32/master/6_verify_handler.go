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

package master

import (
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type verifyHandler struct {
	*resultHandler
}

func newVerifyHandler(oh *resultHandler) *verifyHandler {
	return &verifyHandler{
		resultHandler: oh,
	}
}
func (s *verifyHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Verify)
}

func (s *verifyHandler) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *verifyHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *verifyHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	shareGMsg := msg.GetVerify().GetShareGProofMsg()
	err := shareGMsg.Verify(ecpointgrouplaw.NewBase(curve))
	if err != nil {
		logger.Warn("Failed to verify Schorr proof", "err", err)
		return err
	}
	shareG, err := shareGMsg.V.ToPoint()
	if err != nil {
		logger.Warn("Failed to get ec point", "err", err)
		return err
	}
	err = s.bks.ValidatePublicKey([]*pt.ECPoint{
		s.shareG,
		shareG,
	}, Threshold, s.publicKey)
	if err != nil {
		logger.Warn("Failed to validate coefficients", "err", err)
		return err
	}
	return peer.AddMessage(msg)
}

func (s *verifyHandler) Finalize(logger log.Logger) (types.Handler, error) {
	return nil, nil
}
