// Copyright © 2022 AMIS Technologies
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

package signSix

import (
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type round3Data struct {
	delta *big.Int
	z1hat *pt.ECPoint
	z2hat *pt.ECPoint
}

type round3Handler struct {
	*round2Handler
}

func newRound3Handler(round2Handler *round2Handler) (*round3Handler, error) {
	return &round3Handler{
		round2Handler: round2Handler,
	}, nil
}

func (p *round3Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round3)
}

func (p *round3Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round3Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round3Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}
	round3 := msg.GetRound3()
	// Compute r=R|x-axis and σi =km+rχ.
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	G := pt.NewBase(curve)
	otherPed := peer.para
	// Verify phipai
	phipai, err := paillierzkproof.NewKnowExponentAndPaillierEncryption(parameter, p.own.ssidWithBk, p.gamma, p.nu, p.gammaCiphertext, p.paillierKey.GetN(), otherPed, p.Gamma, G)
	if err != nil {
		return err
	}
	z1hat, err := round3.Z1Hat.ToPoint()
	if err != nil {
		return err
	}
	z2hat, err := round3.Z2Hat.ToPoint()
	if err != nil {
		return err
	}
	otherDelta := new(big.Int).SetBytes(round3.Delta)
	otherDelta.Mod(otherDelta, curveN)
	peer.round3Data = &round3Data{
		delta: otherDelta,
		z1hat: z1hat,
		z2hat: z2hat,
	}

	p.peerManager.MustSend(id, &Message{
		Id:   p.own.Id,
		Type: Type_Round4,
		Body: &Message_Round4{
			Round4: &Round4Msg{
				Gamma:  p.msgGamma,
				Psipai: phipai,
			},
		},
	})

	return peer.AddMessage(msg)
}

func (p *round3Handler) Finalize(logger log.Logger) (types.Handler, error) {
	return newRound4Handler(p)
}
