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
	"errors"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/mta"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	// ErrUnexpectedPublickey is returned if the public key is unexpected
	ErrUnexpectedPublickey = errors.New("unexpected public key")
)

type mtaData struct {
	aiAlpha *big.Int
	wiAlpha *big.Int
	wiG     *pt.ECPoint
}

type mtaHandler struct {
	*encKHandler

	deltaI *big.Int
	tmpSi  *big.Int
}

func newMtaHandler(p *encKHandler) (*mtaHandler, error) {
	return &mtaHandler{
		encKHandler: p,
	}, nil
}

func (p *mtaHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Mta)
}

func (p *mtaHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *mtaHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.mta != nil
}

func (p *mtaHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetMta()
	aiAlpha, err := p.aiMta.Decrypt(new(big.Int).SetBytes(body.EncAiAlpha))
	if err != nil {
		logger.Warn("Failed to decrypt EncAiAlpha", "err", err)
		return err
	}
	wiAlpha, err := p.wiMta.Decrypt(new(big.Int).SetBytes(body.EncWiAlpha))
	if err != nil {
		logger.Warn("Failed to decrypt EncWiAlpha", "err", err)
		return err
	}
	wiG, err := p.wiMta.VerifyProofWithCheck(body.WiProof, p.getCurve(), wiAlpha)
	if err != nil {
		logger.Warn("Failed to verify wi beta proof", "err", err)
		return err
	}
	peer.mta = &mtaData{
		aiAlpha: aiAlpha,
		wiAlpha: wiAlpha,
		wiG:     wiG,
	}
	return peer.AddMessage(msg)
}

func (p *mtaHandler) Finalize(logger log.Logger) (types.Handler, error) {
	err := p.ensurePublickey(logger)
	if err != nil {
		return nil, err
	}
	p.deltaI, p.tmpSi, err = computeDeltaIAndSi(logger, p.aiMta, p.wiMta, p.peers)
	if err != nil {
		return nil, err
	}
	// Send out delta message
	msg := p.getDeltaMessage()
	p.broadcast(msg)
	return newDeltaHandler(p)
}

func (p *mtaHandler) getDeltaMessage() *Message {
	return &Message{
		Type: Type_Delta,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Delta{
			Delta: &BodyDelta{
				Delta: p.deltaI.Bytes(),
			},
		},
	}
}

// Expect the sum of wg is the expected public key
func (p *mtaHandler) ensurePublickey(logger log.Logger) error {
	var err error
	sum := p.wiG
	for id, peer := range p.peers {
		sum, err = sum.Add(peer.mta.wiG)
		if err != nil {
			logger.Warn("Failed to add wg", "id", id, "err", err)
			return err
		}

	}
	if !p.publicKey.Equal(sum) {
		logger.Warn("Unexpected public key", "exp", p.publicKey, "got", sum)
		return ErrUnexpectedPublickey
	}
	return nil
}

func computeDeltaIAndSi(logger log.Logger, aiMta mta.Mta, wiMta mta.Mta, peers map[string]*peer) (*big.Int, *big.Int, error) {
	peerNum := len(peers)
	var (
		aiAlpha = make([]*big.Int, peerNum)
		aiBeta  = make([]*big.Int, peerNum)
		wiAlpha = make([]*big.Int, peerNum)
		wiBeta  = make([]*big.Int, peerNum)
	)
	i := 0
	for _, peer := range peers {
		aiAlpha[i] = peer.mta.aiAlpha
		wiAlpha[i] = peer.mta.wiAlpha
		aiBeta[i] = peer.enck.aiBeta
		wiBeta[i] = peer.enck.wiBeta
		i++
	}
	var err error
	deltaI, err := aiMta.GetResult(aiAlpha, aiBeta)
	if err != nil {
		logger.Warn("Failed to get result from ai mta", "err", err)
		return nil, nil, err
	}
	tmpSi, err := wiMta.GetResult(wiAlpha, wiBeta)
	if err != nil {
		logger.Warn("Failed to get result from wi mta", "err", err)
		return nil, nil, err
	}
	return deltaI, tmpSi, nil
}
