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

package signer

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/oprf"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/sirius/log"
)

type oprfUserData struct {
	response *oprf.OprfResponseMessage
}

type passwordUserHandler struct {
	*pubkeyHandler

	rank                 uint32
	threshold            uint32
	fieldOrder           *big.Int
	peerManager          types.PeerManager
	peerNum              uint32
	oprfRequester        *oprf.Requester
	peers                map[string]*oprfUserData
	share                *big.Int
	newPubkeyHandlerFunc func(secret *big.Int) (*pubkeyHandler, error)
}

// Only support secp256k1 curve and 2-of-2 case
func newPasswordUserHandler(publicKey *pt.ECPoint, peerManager types.PeerManager, homo homo.Crypto, password []byte, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte) (*passwordUserHandler, error) {
	fieldOrder := passwordCurve.N
	peerNum := peerManager.NumPeers()
	err := ensureBksAndPeerNum(publicKey.GetCurve(), peerNum, bks)
	if err != nil {
		return nil, err
	}
	requester, err := oprf.NewRequester(password)
	if err != nil {
		return nil, err
	}
	// Construct peers
	peers := make(map[string]*oprfUserData, peerNum)
	for _, peerID := range peerManager.PeerIDs() {
		peers[peerID] = &oprfUserData{}
	}
	return &passwordUserHandler{
		rank:          tss.PasswordRank,
		threshold:     tss.PasswordThreshold,
		fieldOrder:    fieldOrder,
		peerManager:   peerManager,
		peerNum:       peerNum,
		oprfRequester: requester,
		peers:         peers,
		newPubkeyHandlerFunc: func(secret *big.Int) (*pubkeyHandler, error) {
			return newPubkeyHandler(publicKey, peerManager, homo, secret, bks, msg)
		},
	}, nil
}

func (p *passwordUserHandler) MessageType() types.MessageType {
	return types.MessageType(Type_OPRFResponse)
}

func (p *passwordUserHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *passwordUserHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.response != nil
}

func (p *passwordUserHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}
	res := msg.GetOprfResponse()
	peer.response = res
	var err error
	p.share, err = p.oprfRequester.Compute(res)
	if err != nil {
		logger.Debug("Failed to compute", "err", err)
		return err
	}
	return nil
}

func (p *passwordUserHandler) Finalize(logger log.Logger) (types.Handler, error) {
	var err error
	p.pubkeyHandler, err = p.newPubkeyHandlerFunc(p.share)
	if err != nil {
		logger.Debug("Failed to new pubkey handler", "err", err)
		return nil, err
	}
	tss.Broadcast(p.peerManager, p.pubkeyHandler.GetFirstMessage())
	return p.pubkeyHandler, nil
}

func (p *passwordUserHandler) GetFirstMessage() *Message {
	return &Message{
		Type: Type_OPRFRequest,
		Id:   p.peerManager.SelfID(),
		Body: &Message_OprfRequest{
			OprfRequest: p.oprfRequester.GetRequestMessage(),
		},
	}
}

func (p *passwordUserHandler) GetPubKHandler() *pubkeyHandler {
	return p.pubkeyHandler
}
