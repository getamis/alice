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

package signer

import (
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type round2 struct {
	*round1

	z *big.Int
}

func newRound2(r *round1) (*round2, error) {
	return &round2{
		round1: r,
	}, nil
}

func (p *round2) MessageType() types.MessageType {
	return types.MessageType(Type_Round2)
}

func (p *round2) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round2) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.nodes[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round2) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.nodes[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}
	return peer.AddMessage(msg)
}

func (p *round2) Finalize(logger log.Logger) (types.Handler, error) {
	z := big.NewInt(0)
	G := ecpointgrouplaw.NewBase(p.pubKey.GetCurve())
	isREvenY := isYEven(p.r)
	isPubKeyEvenY := isYEven(p.pubKey)
	for _, node := range p.nodes {
		// Calculate S
		msgBody := node.GetMessage(types.MessageType(Type_Round2)).(*Message).GetRound2()
		node.zi = new(big.Int).SetBytes(msgBody.Zi)
		z.Add(z, node.zi)
		ziG := G.ScalarMult(node.zi)
		ri := node.ri
		if !isREvenY {
			ri = ri.Neg()
		}
		YCopy := node.Y.Copy()
		if !isPubKeyEvenY {
			YCopy = YCopy.Neg()
		}

		cbi := new(big.Int).Mul(node.coBk, p.c)
		cbi.Mod(cbi, p.pubKey.GetCurve().Params().N)
		comparePart, err := YCopy.ScalarMult(cbi).Add(ri)
		if err != nil {
			logger.Debug("Failed to ScalarMult", "err", err)
			return nil, err
		}
		if !comparePart.Equal(ziG) {
			logger.Debug("Inconsistent ziG", "comparePart", comparePart, "ziG", ziG)
			return nil, ErrVerifyFailure
		}
	}
	p.z = z.Mod(z, p.curveN)
	if p.z.Cmp(big0) == 0 {
		return nil, ErrTrivialSignature
	}
	return nil, nil
}

// Different curves for Schnorr signature has different rules.
func isYEven(R *ecpointgrouplaw.ECPoint) bool {
	curve := R.GetCurve()
	switch curve {
	// Taproot verification
	case elliptic.Secp256k1():
		return R.IsEvenY()
	case elliptic.Ed25519():
		return true
	}
	return true
}
