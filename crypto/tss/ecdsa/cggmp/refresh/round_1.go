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

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	commitment "github.com/getamis/alice/crypto/commitment"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/utils"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

const (
	BYTELENGTHKAPPA = 32
)

var (
	ErrNotEnoughRanks = errors.New("not enough ranks")
)

type round1Handler struct {
	ssid        []byte
	paillierKey *paillier.Paillier
	pubKey      *ecpointgrouplaw.ECPoint
	threshold   uint32
	ownBK       *birkhoffinterpolation.BkParameter

	y              *big.Int
	tau            *big.Int // Schnorr commitment of y
	poly           *polynomial.Polynomial
	feldCommitment *commitment.FeldmanCommitmenter
	rho            []byte
	u              []byte // salt
	ped            *paillier.PederssenParameter
	pedParZkproof  *paillierzkproof.RingPederssenParameterMessage
	V              *commitment.HashCommitmenter
	ai             map[string]*big.Int // Schnorr commitment of shares

	bks map[string]*birkhoffinterpolation.BkParameter

	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
}

func newRound1Handler(pubKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, threshold uint32, bks map[string]*birkhoffinterpolation.BkParameter, keySize int, ssid []byte) (*round1Handler, error) {
	numPeers := peerManager.NumPeers()
	// curve := pubKey.GetCurve()
	// Generate 4*kappa long safe primes p, q with N = p*q
	paillierKey, err := paillier.NewPaillierSafePrime(keySize)
	if err != nil {
		return nil, err
	}
	// Set pederssen parameter from paillierKey: Sample r in Z_N^ast, lambda = Z_phi(N), t = r^2 and s = t^lambda mod N
	ped, err := paillierKey.NewPedersenParameterByPaillier()
	if err != nil {
		return nil, err
	}

	p := &round1Handler{
		ssid:        ssid,
		paillierKey: paillierKey,
		pubKey:      pubKey,
		threshold:   threshold,
		bks:         bks,
		ownBK:       bks[peerManager.SelfID()],

		peerNum:     numPeers,
		peers:       buildPeers(peerManager),
		peerManager: peerManager,
	}
	curve := pubKey.GetCurve()
	// Sample y in F_q and Set Y = y*G. And compute Schnorr commitment.
	y, err := utils.RandomInt(curve.Params().N)
	if err != nil {
		return nil, err
	}
	Y := pt.ScalarBaseMult(curve, y)
	msgY, err := Y.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	tau, err := utils.RandomInt(curve.Params().N)
	if err != nil {
		return nil, err
	}
	B := pt.ScalarBaseMult(curve, tau)
	msgB, err := B.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	// Generate polynomial commitment f(x) with f(0) mod q.
	poly, err := polynomial.RandomPolynomial(curve.Params().N, p.threshold-1)
	if err != nil {
		return nil, err
	}
	poly.SetConstant(big.NewInt(0))

	// Build polynomial commitmenter with Xi
	feldmanCommitmenter, err := commitment.NewFeldmanCommitmenter(curve, poly)
	if err != nil {
		return nil, err
	}
	// Generate psi^hat := prm zk proof
	pedPar, err := paillierzkproof.NewRingPederssenParameterMessage(cggmp.ComputeZKSsid(ssid, p.ownBK), ped.GetEulerValue(), ped.PedersenOpenParameter.Getn(), ped.PedersenOpenParameter.Gets(), ped.PedersenOpenParameter.Gett(), ped.Getlambda(), paillierzkproof.MINIMALCHALLENGE)
	if err != nil {
		return nil, err
	}
	Ai := make(map[string]*big.Int)
	msgAi := make(map[string]*pt.EcPointMessage)
	for i := 0; i < len(peerManager.PeerIDs()); i++ {
		temp, err := utils.RandomInt(curve.Params().N)
		if err != nil {
			return nil, err
		}
		Ai[peerManager.PeerIDs()[i]] = temp
		tempPoint := pt.ScalarBaseMult(curve, temp)
		MsgTempPoint, err := tempPoint.ToEcPointMessage()
		if err != nil {
			return nil, err
		}
		msgAi[peerManager.PeerIDs()[i]] = MsgTempPoint
	}

	// Sample rho, u in {0,1}^kappa
	rhoi, err := utils.GenRandomBytes(BYTELENGTHKAPPA)
	if err != nil {
		return nil, err
	}
	ui, err := utils.GenRandomBytes(BYTELENGTHKAPPA)
	if err != nil {
		return nil, err
	}
	// Compute Vi = H(ssid, i, X, A, Y, B, N, s, t, psi^hat, rho, u)
	inputData := &HashMsg{
		PointCommitment: feldmanCommitmenter.GetCommitmentMessage(),
		Y:               msgY,
		PedPar:          pedPar,
		Rho:             rhoi,
		U:               ui,
		Ssid:            ssid,
		Bk:              []byte(p.ownBK.String()),
		A:               msgAi,
		B:               msgB,
	}
	p.V, err = commitment.NewProtoHashCommitmenter(inputData)
	if err != nil {
		return nil, err
	}
	p.feldCommitment = feldmanCommitmenter
	p.y = y
	p.poly = poly
	p.rho = rhoi
	p.u = ui
	p.paillierKey = paillierKey
	p.ped = ped
	p.pedParZkproof = pedPar
	p.tau = tau
	p.ai = Ai
	return p, nil
}

func (p *round1Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round1)
}

func (p *round1Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round1Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round1Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}
	return peer.AddMessage(msg)
}

func (p *round1Handler) Finalize(logger log.Logger) (types.Handler, error) {
	cggmp.Broadcast(p.peerManager, &Message{
		Type: Type_Round2,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Round2{
			Round2: &Round2Msg{
				Decommitment: p.V.GetDecommitmentMessage(),
			},
		},
	})
	return newRound2Handler(p), nil
}

func (p *round1Handler) getRound1Message() *Message {
	return &Message{
		Type: Type_Round1,
		Id:   p.peerManager.SelfID(),
		Body: &Message_Round1{
			Round1: &Round1Msg{
				Commitment: p.V.GetCommitmentMessage(),
			},
		},
	}
}

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}

func buildPeers(peerManager types.PeerManager) map[string]*peer {
	peers := make(map[string]*peer, peerManager.NumPeers())
	for _, id := range peerManager.PeerIDs() {
		peers[id] = newPeer(id)
	}
	return peers
}
