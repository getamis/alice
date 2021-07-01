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
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/oprf"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/internal/message"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

const (
	maxRetry = 100
)

var (
	big1          = big.NewInt(1)
	passwordCurve = btcec.S256()

	ErrInvalidPeerNum = errors.New("invalid peer number")
	ErrInvalidUserX   = errors.New("invalid user x")
	ErrFailedGenX     = errors.New("failed to generate x")
)

type oprfServerData struct {
	request *BodyOPRFRequest
}

type passwordServerHandler struct {
	*peerHandler

	rank          uint32
	threshold     uint32
	fieldOrder    *big.Int
	peerManager   types.PeerManager
	peerNum       uint32
	oprfResponser *oprf.Responser
	userX         *big.Int
	peers         map[string]*oprfServerData
}

// Only support secp256k1 curve and 2-of-2 case
func newPasswordPeerServerHandler(peerManager types.PeerManager) (*passwordServerHandler, error) {
	fieldOrder := passwordCurve.N
	peerNum := peerManager.NumPeers()
	if peerNum != tss.PasswordN-1 {
		return nil, ErrInvalidPeerNum
	}
	responser, err := oprf.NewResponser()
	if err != nil {
		return nil, err
	}
	// Construct peers
	peers := make(map[string]*oprfServerData, peerNum)
	for _, peerID := range peerManager.PeerIDs() {
		peers[peerID] = &oprfServerData{}
	}
	return &passwordServerHandler{
		rank:          tss.PasswordRank,
		threshold:     tss.PasswordThreshold,
		fieldOrder:    fieldOrder,
		peerManager:   peerManager,
		peerNum:       peerNum,
		oprfResponser: responser,
		peers:         peers,
	}, nil
}

func (p *passwordServerHandler) MessageType() types.MessageType {
	return types.MessageType(Type_OPRFRequest)
}

func (p *passwordServerHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *passwordServerHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return false
	}
	return peer.request != nil
}

func (p *passwordServerHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Debug("Peer not found")
		return tss.ErrPeerNotFound
	}
	request := msg.GetOprfRequest()
	peer.request = request

	// Check user x
	p.userX = new(big.Int).SetBytes(request.X)
	if err := utils.InRange(p.userX, big1, p.fieldOrder); err != nil {
		logger.Debug("Invalid user x")
		return ErrInvalidUserX
	}

	// Check request
	res, err := p.oprfResponser.Handle(request.Request)
	if err != nil {
		logger.Debug("Failed to handle oprf", "err", err)
		return err
	}
	p.peerManager.MustSend(id, &Message{
		Type: Type_OPRFResponse,
		Id:   p.peerManager.SelfID(),
		Body: &Message_OprfResponse{
			OprfResponse: res,
		},
	})
	return nil
}

func (p *passwordServerHandler) Finalize(logger log.Logger) (types.Handler, error) {
	poly, err := polynomial.RandomPolynomialWithSpecialValueAtPoint(p.userX, big.NewInt(0), p.fieldOrder, p.threshold-1)
	if err != nil {
		logger.Debug("Failed to expand", "err", err)
		return nil, err
	}

	// Random x
	x, err := p.getRandomX()
	if err != nil {
		logger.Debug("Failed to generate x", "err", err)
		return nil, err
	}

	p.peerHandler, err = newPeerHandlerWithPolynomial(passwordCurve, p.peerManager, p.threshold, x, p.rank, poly)
	if err != nil {
		logger.Debug("Failed to new peer handler", "err", err)
		return nil, err
	}
	message.Broadcast(p.peerManager, p.peerHandler.GetFirstMessage())
	return p.peerHandler, nil
}

func (p *passwordServerHandler) GetFirstMessage() *Message {
	return nil
}

func (p *passwordServerHandler) GetPeerHandler() *peerHandler {
	return p.peerHandler
}

func (p *passwordServerHandler) getRandomX() (*big.Int, error) {
	for i := 0; i < maxRetry; i++ {
		x, err := utils.RandomPositiveInt(p.fieldOrder)
		if err != nil {
			continue
		}
		return x, nil
	}
	return nil, ErrFailedGenX
}
