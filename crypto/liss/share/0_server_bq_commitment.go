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
	"errors"
	"math/big"

	bqForm "github.com/getamis/alice/crypto/binaryquadraticform"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/liss"
	"github.com/getamis/alice/crypto/matrix"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/libs/message"
	"github.com/getamis/alice/libs/message/types"
	"github.com/getamis/sirius/log"
	"google.golang.org/protobuf/proto"
)

const (
	d                   = 40
	distributedDistance = 40
	bigrange            = uint(15)
	distanceDist        = uint(10)
	safeParameter       = 1348
)

var (
	c             = big.NewInt(1024)
	secp256k1N, _ = new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)
	big1          = big.NewInt(1)
	bit256        = new(big.Int).Lsh(big1, 256)

	//ErrFailedVerify is returned if we verify failed
	ErrFailedVerify = errors.New("failed verify")
)

type bqCommitmentHandler struct {
	configs          liss.GroupConfigs
	configsMatrix    *matrix.Matrix
	salts            [][]byte
	exponential      []*bqForm.BQuadraticForm
	bqMsg            *Message
	shares           [][]map[string]*big.Int
	exponentialM     []*bqForm.BQuadraticForm
	exponentialMMsgs []*bqForm.BQForm
	decommitMsg      []*BqDecommit
	clParameter      *cl.CLBaseParameter

	selfId  string
	pm      types.PeerManager
	peers   map[string]*peer
	peerNum uint32
}

func newBqCommitmentHandler(peerManager types.PeerManager, configs liss.GroupConfigs) (*bqCommitmentHandler, error) {
	clParameter, err := cl.NewCLBaseParameter(c, d, secp256k1N, safeParameter, distributedDistance)
	if err != nil {
		return nil, err
	}

	peers := make(map[string]*peer, peerManager.NumPeers())
	for _, id := range peerManager.PeerIDs() {
		peers[id] = newPeer(id)
	}
	p := &bqCommitmentHandler{
		configs: configs,

		selfId:  peerManager.SelfID(),
		pm:      peerManager,
		peers:   peers,
		peerNum: peerManager.NumPeers(),
	}
	err = p.init(clParameter)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *bqCommitmentHandler) MessageType() types.MessageType {
	return types.MessageType(Type_BqCommitment)
}

func (p *bqCommitmentHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *bqCommitmentHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.GetMessage(p.MessageType()) != nil
}

func (p *bqCommitmentHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}
	peer.commitments = msg.GetBqCommitment().Commitments

	p.pm.MustSend(id, &Message{
		Id:   p.selfId,
		Type: Type_BqDecommitment,
		Body: &Message_BqDedemmitment{
			BqDedemmitment: &BodyBqDecommitment{
				ExpM:          p.exponentialMMsgs,
				Decommitments: p.decommitMsg,
			},
		},
	})
	return peer.AddMessage(msg)
}

func (p *bqCommitmentHandler) Finalize(logger log.Logger) (types.Handler, error) {
	return newBqDecommitmentHandler(p)
}

func (p *bqCommitmentHandler) GetFirstMessage() *Message {
	return p.bqMsg
}

func (p *bqCommitmentHandler) broadcast(msg proto.Message) {
	message.Broadcast(p.pm, msg)
}

func (p *bqCommitmentHandler) init(clParameter *cl.CLBaseParameter) error {
	randomValue, m, err := p.configs.GenerateRandomValue(bigrange, distanceDist)
	if err != nil {
		return err
	}
	g := clParameter.GetG()
	exponential := make([]*bqForm.BQuadraticForm, randomValue.GetNumberRow())
	for i := 0; i < len(exponential); i++ {
		exponential[i], err = g.Exp(randomValue.Get(uint64(i), 0))
		if err != nil {
			return err
		}
	}

	// Generate shares and exponentialM
	shares, exponentialM, err := p.configs.GenerateShares(g, randomValue, m)
	if err != nil {
		return err
	}
	exponentialMMsgs := make([]*bqForm.BQForm, len(exponentialM))
	for i, e := range exponentialM {
		exponentialMMsgs[i] = e.ToMessage()
	}

	// Establish the commitments/decommitments
	salts := make([][]byte, len(exponential))
	commitments := make([][]byte, len(exponential))
	for i := 0; i < len(exponential); i++ {
		tmpMsg := exponential[i].ToMessage()
		hash, salt, err := utils.HashProtosRejectSampling(bit256, tmpMsg)
		if err != nil {
			return err
		}
		commitments[i] = hash.Bytes()
		salts[i] = salt
	}
	decommitMsg := make([]*BqDecommit, len(salts))
	for i := 0; i < len(decommitMsg); i++ {
		decommitMsg[i] = &BqDecommit{
			Salt:   salts[i],
			Bqform: exponential[i].ToMessage(),
		}
	}
	p.configsMatrix = m
	p.salts = salts
	p.exponential = exponential
	p.bqMsg = &Message{
		Id:   p.pm.SelfID(),
		Type: Type_BqCommitment,
		Body: &Message_BqCommitment{
			BqCommitment: &BodyBqCommitment{
				ClBase:      clParameter.ToMessage(),
				Commitments: commitments,
			},
		},
	}
	p.shares = shares
	p.exponentialM = exponentialM
	p.exponentialMMsgs = exponentialMMsgs
	p.decommitMsg = decommitMsg
	p.clParameter = clParameter
	return nil
}

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}

func getMessageByType(peer *peer, t Type) *Message {
	return getMessage(peer.GetMessage(types.MessageType(t)))
}
