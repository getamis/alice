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
	"github.com/getamis/alice/crypto/liss"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type bqCommitmentUserHandler struct {
	bqCommitmentHandler
}

func newbqCommitmentUserHandler(peerManager types.PeerManager, configs liss.GroupConfigs) (*bqCommitmentUserHandler, error) {
	peers := make(map[string]*peer, peerManager.NumPeers())
	for _, id := range peerManager.PeerIDs() {
		peers[id] = newPeer(id)
	}
	return &bqCommitmentUserHandler{
		bqCommitmentHandler: bqCommitmentHandler{
			configs: configs,

			selfId:  peerManager.SelfID(),
			pm:      peerManager,
			peers:   peers,
			peerNum: peerManager.NumPeers(),
		},
	}, nil
}

func (p *bqCommitmentUserHandler) MessageType() types.MessageType {
	return types.MessageType(Type_BqCommitment)
}

func (p *bqCommitmentUserHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *bqCommitmentUserHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *bqCommitmentUserHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}
	peer.commitments = msg.GetBqCommitment().Commitments
	// handle cl base message
	clBase, err := msg.GetBqCommitment().ClBase.ToBase(c, d, secp256k1N, safeParameter, distributedDistance)
	if err != nil {
		logger.Debug("Failed to get cl base", "err", err)
		return err
	}
	err = p.init(clBase)
	if err != nil {
		logger.Debug("Failed to init", "err", err)
		return err
	}
	p.pm.MustSend(id, p.bqMsg)

	return peer.AddMessage(msg)
}

func (p *bqCommitmentUserHandler) Finalize(logger log.Logger) (types.Handler, error) {
	p.broadcast(&Message{
		Id:   p.selfId,
		Type: Type_BqDecommitment,
		Body: &Message_BqDedemmitment{
			BqDedemmitment: &BodyBqDecommitment{
				ExpM:          p.exponentialMMsgs,
				Decommitments: p.decommitMsg,
			},
		},
	})
	return newBqDecommitmentHandler(&p.bqCommitmentHandler)
}
