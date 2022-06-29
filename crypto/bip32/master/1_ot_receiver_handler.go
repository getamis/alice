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
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type otReceiver struct {
	*initial
}

func newOtReceiver(ih *initial) *otReceiver {
	return &otReceiver{
		initial: ih,
	}
}
func (s *otReceiver) MessageType() types.MessageType {
	return types.MessageType(Type_OtReceiver)
}

func (s *otReceiver) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *otReceiver) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *otReceiver) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetOtReceiver()
	senderResponseMsg, err := s.otExtSender.Verify(body.GetOtExtReceiveMsg())
	if err != nil {
		logger.Warn("Failed to verify ot ext receiver", "err", err)
		return err
	}
	s.peerManager.MustSend(id, &Message{
		Type: Type_OtSendResponse,
		Id:   s.selfId,
		Body: &Message_OtSendResponse{
			OtSendResponse: &BodyOtSendResponse{
				OtExtSendResponseMsg: senderResponseMsg,
			},
		},
	})
	return peer.AddMessage(msg)
}

func (s *otReceiver) Finalize(logger log.Logger) (types.Handler, error) {
	return newOtSendResponse(s), nil
}
