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
	"crypto/elliptic"
	"errors"
	fmt "fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/oprf"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/libs/message"
	"github.com/getamis/alice/libs/message/types"
	"github.com/getamis/sirius/log"
)

const (
	maxRetry = 100
)

var (
	big1          = big.NewInt(1)
	passwordCurve = btcec.S256()

	ErrNotS256Curve   = errors.New("not S256 curve")
	ErrInvalidPeerNum = errors.New("invalid peer number")
	ErrInvalidBk      = errors.New("invalid bk")
)

type oprfServerData struct {
	request *oprf.OprfRequestMessage
}

type passwordServerHandler struct {
	*pubkeyHandler

	rank          uint32
	threshold     uint32
	fieldOrder    *big.Int
	peerManager   types.PeerManager
	peerNum       uint32
	oprfResponser *oprf.Responser
	peers         map[string]*oprfServerData
}

// Only support secp256k1 curve and 2-of-2 case
func newPasswordServerHandler(publicKey *pt.ECPoint, peerManager types.PeerManager, homo homo.Crypto, secret *big.Int, k *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte) (*passwordServerHandler, error) {
	fieldOrder := passwordCurve.N
	peerNum := peerManager.NumPeers()
	err := ensureBksAndPeerNum(publicKey.GetCurve(), peerNum, bks)
	if err != nil {
		return nil, err
	}
	responser, err := oprf.NewResponserWithK(k)
	if err != nil {
		return nil, err
	}
	// Construct peers
	peers := make(map[string]*oprfServerData, peerNum)
	for _, peerID := range peerManager.PeerIDs() {
		peers[peerID] = &oprfServerData{}
	}
	pubkeyHandler, err := newPubkeyHandler(publicKey, peerManager, homo, secret, bks, msg, true)
	if err != nil {
		return nil, err
	}
	return &passwordServerHandler{
		pubkeyHandler: pubkeyHandler,
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

	// Check request
	res, err := p.oprfResponser.Handle(request)
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
	message.Broadcast(p.peerManager, p.pubkeyHandler.GetFirstMessage())
	return p.pubkeyHandler, nil
}

func (p *passwordServerHandler) GetFirstMessage() *Message {
	return nil
}

func (p *passwordServerHandler) GetPubKHandler() *pubkeyHandler {
	return p.pubkeyHandler
}

func ensureBksAndPeerNum(curve elliptic.Curve, peerNum uint32, bks map[string]*birkhoffinterpolation.BkParameter) error {
	if curve != btcec.S256() {
		return ErrNotS256Curve
	}
	if peerNum != tss.PasswordN-1 {
		return ErrInvalidPeerNum
	}
	for _, bk := range bks {
		if bk.GetRank() != tss.PasswordRank {
			fmt.Println("x", bk.GetX(), "rank", bk.GetRank())
			return ErrInvalidBk
		}
	}
	return nil
}
