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

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/mta"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type encKData struct {
	aiBeta *big.Int
	wiBeta *big.Int
	mtaMsg *Message
}

type encKHandler struct {
	*pubkeyHandler

	wiMta mta.Mta
	wiG   *pt.ECPoint
}

func newEncKHandler(p *pubkeyHandler) (*encKHandler, error) {
	// Build mta for wi, g
	wiMta, err := p.aiMta.OverrideA(p.wi)
	if err != nil {
		log.Warn("Failed to create wi mta", "wi", p.wi, "err", err)
		return nil, err
	}

	curve := p.getCurve()
	wiG := pt.ScalarBaseMult(curve, p.wi)
	return &encKHandler{
		pubkeyHandler: p,

		wiMta: wiMta,
		wiG:   wiG,
	}, nil
}

func (p *encKHandler) MessageType() types.MessageType {
	return types.MessageType(Type_EncK)
}

func (p *encKHandler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *encKHandler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.enck != nil
}

func (p *encKHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	// Compute alpha and beta
	body := msg.GetEncK()
	encAiAlpha, aiBeta, err := p.aiMta.Compute(peer.pubkey.publicKey, body.Enck)
	if err != nil {
		logger.Warn("Failed to compute for ai mta", "err", err)
		return err
	}
	encWiAlpha, wiBeta, err := p.wiMta.Compute(peer.pubkey.publicKey, body.Enck)
	if err != nil {
		logger.Warn("Failed to compute for wi mta", "err", err)
		return err
	}
	wiProof, err := p.wiMta.GetProofWithCheck(p.getCurve(), wiBeta)
	if err != nil {
		logger.Warn("Failed to compute beta proof", "err", err)
		return err
	}

	peer.enck = &encKData{
		aiBeta: aiBeta,
		wiBeta: wiBeta,
		mtaMsg: &Message{
			Type: Type_Mta,
			Id:   p.peerManager.SelfID(),
			Body: &Message_Mta{
				Mta: &BodyMta{
					EncAiAlpha: encAiAlpha.Bytes(),
					EncWiAlpha: encWiAlpha.Bytes(),
					WiProof:    wiProof,
				},
			},
		},
	}
	return peer.AddMessage(msg)
}

func (p *encKHandler) Finalize(logger log.Logger) (types.Handler, error) {
	for id, peer := range p.peers {
		p.peerManager.MustSend(id, peer.enck.mtaMsg)
	}
	return newMtaHandler(p)
}
