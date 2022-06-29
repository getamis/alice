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

	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type round3Data struct {
	plaintextShareBig    *big.Int
	partialRefreshPubkey *pt.ECPoint
}

type Result struct {
	refreshShare     *big.Int
	sumpartialPubKey *pt.ECPoint
}

type round3Handler struct {
	*round2Handler

	result *Result
}

var (
	big1 = big.NewInt(1)

	// ErrDifferentPoint is returned if the two points are different.
	ErrDifferentPoint = errors.New("the two points are different")
)

func newRound3Handler(r *round2Handler) *round3Handler {
	return &round3Handler{
		round2Handler: r,
	}
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

	curve := p.pubKey.GetCurve()
	round3Msg := msg.GetRound3()
	plaintextShare, err := p.paillierKey.Decrypt(round3Msg.Encshare)
	if err != nil {
		logger.Warn("Failed to decrypted", "err", err)
		return err
	}

	polyPoint, err := peer.round2.hashMsg.PointCommitment.EcPoints()
	if err != nil {
		logger.Warn("Failed to EcPoints", "err", err)
		return err
	}
	plaintextShareBig := new(big.Int).SetBytes(plaintextShare)
	ped := p.ped.PedersenOpenParameter

	// verify Feldmann commitment
	err = commitment.FeldmanVerify(curve, p.ownBK, polyPoint, p.threshold-1, plaintextShareBig)
	if err != nil {
		// mu = (cipherShare * (1+n)^(-share))(^1/n) mod n^2.
		n := ped.Getn()
		mu := new(big.Int).Add(big1, n)
		mu.Exp(mu, new(big.Int).Neg(plaintextShareBig), p.paillierKey.GetNSquare())
		mu.Mul(mu, new(big.Int).SetBytes(round3Msg.Encshare))
		mu.Mod(mu, p.paillierKey.GetNSquare())
		// Notice: we have assume that n = pedN
		mu.Exp(mu, new(big.Int).ModInverse(n, p.ped.GetEulerValue()), p.paillierKey.GetNSquare())
		errMsg := &AuxiliaryInfoKeyRefeshErrorMessage{
			Ciphertext: round3Msg.Encshare,
			Plaintext:  plaintextShare,
			Mu:         mu.Bytes(),
		}
		return errors.New(errMsg.String())
	}

	// Generate SSID Info + sumro
	ssidSumRho := append(cggmp.ComputeZKSsid(p.ssid, p.bks[id]), []byte("!")...)
	ssidSumRho = append(ssidSumRho, p.sumrho...)
	// Verify factor proof
	err = round3Msg.FacProof.Verify(paillierzkproof.NewS256(),
		ssidSumRho, p.sumrho, peer.round2.pederssenPara.Getn(), ped)
	if err != nil {
		return err
	}

	// Verify mod Proof
	err = round3Msg.ModProof.Verify(ssidSumRho, peer.round2.pederssenPara.Getn())
	if err != nil {
		return err
	}

	// check commitment
	Y, err := round3Msg.YschnorrProof.V.ToPoint()
	if err != nil {
		return err
	}
	if !peer.round2.y.Equal(Y) {
		return ErrDifferentPoint
	}
	B, err := p.peers[id].round2.hashMsg.B.ToPoint()
	if err != nil {
		return err
	}
	Bhat, err := round3Msg.YschnorrProof.Alpha.ToPoint()
	if err != nil {
		return err
	}
	if !B.Equal(Bhat) {
		return ErrDifferentPoint
	}
	Ai, err := p.peers[id].round2.hashMsg.A[p.peerManager.SelfID()].ToPoint()
	if err != nil {
		return err
	}
	Aihat, err := round3Msg.ShareschnorrProof.Alpha.ToPoint()
	if err != nil {
		return err
	}
	if !Ai.Equal(Aihat) {
		return ErrDifferentPoint
	}

	G := pt.NewBase(curve)
	err = round3Msg.YschnorrProof.Verify(G, ssidSumRho)
	if err != nil {
		return err
	}
	err = round3Msg.ShareschnorrProof.Verify(G, ssidSumRho)
	if err != nil {
		return err
	}

	peer.round3 = &round3Data{
		plaintextShareBig:    plaintextShareBig,
		partialRefreshPubkey: pt.ScalarBaseMult(curve, plaintextShareBig),
	}
	return peer.AddMessage(msg)
}

func (p *round3Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curve := p.pubKey.GetCurve()
	refreshShare := new(big.Int).Set(p.refreshShare)
	sumpartialPubKey := pt.ScalarBaseMult(curve, p.refreshShare)
	var err error
	for _, peer := range p.peers {
		plaintextShareBig := peer.round3.plaintextShareBig
		refreshShare = refreshShare.Add(refreshShare, plaintextShareBig)
		sumpartialPubKey, err = sumpartialPubKey.Add(pt.ScalarBaseMult(curve, plaintextShareBig))
		if err != nil {
			return nil, err
		}
	}
	p.result = &Result{
		refreshShare:     refreshShare,
		sumpartialPubKey: sumpartialPubKey,
	}
	return nil, nil
}
