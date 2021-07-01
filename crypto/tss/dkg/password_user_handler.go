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

package dkg

import (
	"math/big"

	"github.com/getamis/alice/crypto/oprf"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/internal/message"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type oprfUserData struct {
	response *oprf.OprfResponseMessage
}

type passwordUserHandler struct {
	*peerHandler

	rank          uint32
	threshold     uint32
	fieldOrder    *big.Int
	peerManager   types.PeerManager
	peerNum       uint32
	oprfRequester *oprf.Requester
	x             *big.Int
	share         *big.Int
	peers         map[string]*oprfUserData
}

// Only support secp256k1 curve and 2-of-2 case
func newPasswordPeerUserHandler(peerManager types.PeerManager, password []byte) (*passwordUserHandler, error) {
	fieldOrder := passwordCurve.N
	peerNum := peerManager.NumPeers()
	if peerNum != tss.PasswordN-1 {
		return nil, ErrInvalidPeerNum
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
	// Random x and build bk
	x, err := utils.RandomPositiveInt(fieldOrder)
	if err != nil {
		return nil, err
	}
	return &passwordUserHandler{
		rank:          tss.PasswordRank,
		threshold:     tss.PasswordThreshold,
		fieldOrder:    fieldOrder,
		peerManager:   peerManager,
		peerNum:       peerNum,
		oprfRequester: requester,
		x:             x,
		peers:         peers,
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
	share, err := p.oprfRequester.Compute(res)
	if err != nil {
		logger.Debug("Failed to compute", "err", err)
		return err
	}
	p.share = share
	return nil
}

func (p *passwordUserHandler) Finalize(logger log.Logger) (types.Handler, error) {
	poly, err := polynomial.RandomPolynomialWithSpecialValueAtPoint(p.x, p.share, p.fieldOrder, p.threshold-1)
	if err != nil {
		logger.Debug("Failed to expand", "err", err)
		return nil, err
	}

	p.peerHandler, err = newPeerHandlerWithPolynomial(passwordCurve, p.peerManager, p.threshold, p.x, p.rank, poly)
	if err != nil {
		logger.Debug("Failed to new peer handler", "err", err)
		return nil, err
	}
	message.Broadcast(p.peerManager, p.peerHandler.GetFirstMessage())
	return p.peerHandler, nil
}

func (p *passwordUserHandler) GetFirstMessage() *Message {
	return &Message{
		Type: Type_OPRFRequest,
		Id:   p.peerManager.SelfID(),
		Body: &Message_OprfRequest{
			OprfRequest: &BodyOPRFRequest{
				X:       p.x.Bytes(),
				Request: p.oprfRequester.GetRequestMessage(),
			},
		},
	}
}

func (p *passwordUserHandler) GetPeerHandler() *peerHandler {
	return p.peerHandler
}
