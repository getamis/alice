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

package verifier

import (
	"crypto/elliptic"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/oprf"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/sirius/log"
)

type serverHandler0 struct {
	peerManager types.PeerManager
	publicKey   *ecpointgrouplaw.ECPoint
	peers       map[string]*peer
	bks         map[string]*birkhoffinterpolation.BkParameter
	curve       elliptic.Curve

	secret            *big.Int
	passwordResponser *oprf.Responser

	serverGProver *zkproof.InteractiveSchnorrProver
}

func newServerHandler0(publicKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, bks map[string]*birkhoffinterpolation.BkParameter, k *big.Int, secret *big.Int) (*serverHandler0, error) {
	if publicKey.IsIdentity() {
		return nil, ErrIndentityPublicKey
	}
	// Construct peers
	curve := publicKey.GetCurve()
	peers, err := buildPeers(peerManager.SelfID(), curve.Params().N, bks)
	if err != nil {
		return nil, err
	}

	// Build responsers
	oldResponser, err := oprf.NewResponserWithK(k)
	if err != nil {
		return nil, err
	}

	secretProver, err := zkproof.NewInteractiveSchnorrProver(secret, curve)
	if err != nil {
		return nil, err
	}
	return &serverHandler0{
		publicKey:   publicKey,
		peerManager: peerManager,
		peers:       peers,
		bks:         bks,
		curve:       curve,

		secret:            secret,
		passwordResponser: oldResponser,
		serverGProver:     secretProver,
	}, nil
}

func (p *serverHandler0) MessageType() types.MessageType {
	return types.MessageType(Type_MsgUser0)
}

func (p *serverHandler0) GetRequiredMessageCount() uint32 {
	return 1
}

func (p *serverHandler0) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *serverHandler0) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	user0 := msg.GetUser0()
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}

	oldPasswordRes, err := p.passwordResponser.Handle(user0.PasswordRequest)
	if err != nil {
		logger.Debug("Failed to handle old password request", "err", err)
		return err
	}

	// Send out server 0 message
	p.peerManager.MustSend(message.GetId(), &Message{
		Type: Type_MsgServer0,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Server0{
			Server0: &BodyServer0{
				PasswordResponse: oldPasswordRes,
				ServerGProver1:   p.serverGProver.GetInteractiveSchnorrProver1Message(),
			},
		},
	})
	return peer.AddMessage(msg)
}

func (p *serverHandler0) Finalize(logger log.Logger) (types.Handler, error) {
	return newServerHandler1(p)
}
