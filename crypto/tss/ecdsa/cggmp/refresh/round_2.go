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

package refresh

import (
	"errors"
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

const (
	SAFEPUBKEYLENGTH = 2048
)

type round2Data struct {
	share         *big.Int
	encryptShare  *big.Int
	pederssenPara *paillierzkproof.PederssenOpenParameter
	y             *pt.ECPoint
	hashMsg       *HashMsg
	factorProof   *paillierzkproof.NoSmallFactorMessage
}

var (
	big0 = big.NewInt(0)

	// ErrSmallPublicKey is returned if the public key is small.
	ErrSmallPublicKey = errors.New("small public key")
	// ErrTrivialPoint is returned if the the point is the identity point.
	ErrTrivialPoint = errors.New("the identity point")
)

type round2Handler struct {
	*round1Handler

	sumrho       []byte
	refreshShare *big.Int
}

func newRound2Handler(r *round1Handler) *round2Handler {
	return &round2Handler{
		round1Handler: r,
	}
}

func (p *round2Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round2)
}

func (p *round2Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round2Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round2Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	// Get HashMsg with commitments
	round1 := getMessage(peer.GetMessage(types.MessageType(Type_Round1)))
	decommitData := &HashMsg{}
	err := round1.GetRound1().Commitment.DecommitToProto(msg.GetRound2().GetDecommitment(), decommitData)
	if err != nil {
		logger.Warn("Failed to decommit message", "err", err)
		return err
	}

	// Verify HashMsg
	data, err := p.buildRound2Data(id, decommitData)
	if err != nil {
		logger.Warn("Failed to build round2 data", "err", err)
		return err
	}
	peer.round2 = data
	return peer.AddMessage(msg)
}

func (p *round2Handler) buildRound2Data(peerId string, commitData *HashMsg) (*round2Data, error) {
	// 1. Check n >= 2048
	n := new(big.Int).SetBytes(commitData.PedPar.N)
	if n.BitLen() < SAFEPUBKEYLENGTH {
		return nil, ErrSmallPublicKey
	}
	// Check a0G = 0*G
	curve := p.pubKey.GetCurve()
	zeroPoint, err := commitData.PointCommitment.Points[0].ToPoint()
	if err != nil {
		return nil, err
	}
	if !zeroPoint.IsIdentity() {
		return nil, ErrTrivialPoint
	}
	// Verify pederssenPara proof
	bk := p.bks[peerId]
	pubKey, err := paillier.ToPaillierPubKeyWithSpecialGFromMsg(cggmp.ComputeZKSsid(p.ssid, bk), commitData.PedPar)
	if err != nil {
		return nil, err
	}

	// compute share
	diff := p.poly.Differentiate(bk.GetRank())
	xValue := bk.GetX()
	refreshshareplaintext := diff.Evaluate(xValue)
	refreshshareplaintext.Mod(refreshshareplaintext, curve.Params().N)
	tempEnc, err := pubKey.Encrypt(refreshshareplaintext.Bytes())
	if err != nil {
		return nil, err
	}
	// Build round2data
	pederssenPara, err := paillier.NewPedersenOpenParameter(new(big.Int).SetBytes(commitData.PedPar.N), new(big.Int).SetBytes(commitData.PedPar.S), new(big.Int).SetBytes(commitData.PedPar.T))
	if err != nil {
		return nil, err
	}
	Y, err := commitData.Y.ToPoint()
	if err != nil {
		return nil, err
	}
	return &round2Data{
		share:         refreshshareplaintext,
		encryptShare:  new(big.Int).SetBytes(tempEnc),
		pederssenPara: pederssenPara,
		y:             Y,
		hashMsg:       commitData,
	}, nil
}

func (p *round2Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curve := p.pubKey.GetCurve()
	G := pt.NewBase(curve)
	sumrho := make([]byte, BYTELENGTHKAPPA)
	copy(sumrho, p.rho)
	for _, peer := range p.peers {
		round2 := peer.round2
		sumrho = utils.Xor(sumrho, round2.hashMsg.Rho)
	}

	// Build the sum of rho
	p.sumrho = sumrho
	diff := p.poly.Differentiate(p.ownBK.GetRank())
	p.refreshShare = diff.Evaluate(p.ownBK.GetX())

	// Generate SSID Info + sumro
	ssidSumRho := append(cggmp.ComputeZKSsid(p.ssid, p.ownBK), []byte("!")...)
	ssidSumRho = append(ssidSumRho, p.sumrho...)
	for _, peer := range p.peers {
		temp := peer.round2.pederssenPara

		// Compute facProof phi
		// FIXME: select curveconfig
		var err error
		peer.round2.factorProof, err = paillierzkproof.NewNoSmallFactorMessage(paillierzkproof.NewS256(), ssidSumRho, p.sumrho, p.ped.GetP(), p.ped.GetQ(), p.ped.PedersenOpenParameter.Getn(), temp)
		if err != nil {
			return nil, err
		}
	}

	// Generate modProof psi
	modProof, err := paillierzkproof.NewPaillierBlumMessage(ssidSumRho, p.ped.GetP(), p.ped.GetQ(), p.ped.PedersenOpenParameter.Getn(), paillierzkproof.MINIMALCHALLENGE)
	if err != nil {
		return nil, err
	}
	// Generate Schnorr proof pi
	ySchnorrzkproof, err := zkproof.NewSchnorrMessageWithGivenMN(p.y, big0, p.tau, big0, G, ssidSumRho)
	if err != nil {
		return nil, err
	}

	// Send round3 messages
	for id, peer := range p.peers {
		// Generate Schnorr proof psi_i
		xijzkproof, err := zkproof.NewSchnorrMessageWithGivenMN(peer.round2.share, big0, p.ai[id], big0, G, ssidSumRho)
		if err != nil {
			return nil, err
		}
		p.peerManager.MustSend(id, &Message{
			Type: Type_Round3,
			Id:   p.peerManager.SelfID(),
			Body: &Message_Round3{
				Round3: &Round3Msg{
					ModProof:          modProof,
					FacProof:          peer.round2.factorProof,
					YschnorrProof:     ySchnorrzkproof,
					Encshare:          peer.round2.encryptShare.Bytes(),
					ShareschnorrProof: xijzkproof,
				},
			},
		})
	}
	return newRound3Handler(p), nil
}
