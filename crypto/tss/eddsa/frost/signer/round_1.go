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
	"crypto/sha512"
	"errors"
	"math/big"
	"sort"

	"github.com/agl/ed25519/edwards25519"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"github.com/golang/protobuf/ptypes/any"
)

const (
	// maxRetry defines the max retries to generate proof
	maxRetry = 300
)

var (
	bit254 = new(big.Int).Lsh(big.NewInt(1), 253)
	big0   = big.NewInt(0)

	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
	//ErrPeerNotFound is returned if peer message not found.
	ErrPeerNotFound = errors.New("peer message not found")
	//ErrTrivialSignature is returned if obtain trivial signature.
	ErrTrivialSignature = errors.New("obtain trivial signature")
)

type pubkeyData struct {
	publicKey homo.Pubkey
	aigCommit *commitment.HashCommitmentMessage
}

type round1 struct {
	threshold uint32
	message   []byte
	share     *big.Int
	pubKey    *ecpointgrouplaw.ECPoint
	curveN    *big.Int

	peerManager types.PeerManager
	peerNum     uint32
	nodes       map[string]*peer

	ownbk *birkhoffinterpolation.BkParameter

	e *big.Int
	d *big.Int
	Y *ecpointgrouplaw.ECPoint

	round1Msg *Message

	// Results
	r *ecpointgrouplaw.ECPoint
	c *big.Int
}

func newRound1(pubKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, threshold uint32, share *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, message []byte) (*round1, error) {
	selfId := peerManager.SelfID()
	ownbk := bks[selfId]
	curve := pubKey.GetCurve()
	curveN := curve.Params().N
	bbks := make(birkhoffinterpolation.BkParameters, len(bks))
	nodes := make(map[string]*peer, peerManager.NumPeers()+1)
	i := 0
	for id, bk := range bks {
		bbks[i] = bk
		nodes[id] = newPeer(id, i, bk)
		i++
	}
	coBks, err := bbks.ComputeBkCoefficient(threshold, curveN)
	if err != nil {
		return nil, err
	}
	for _, p := range nodes {
		p.coBk = coBks[p.index]
	}

	// Build parameters
	e, err := utils.RandomPositiveInt(curveN)
	if err != nil {
		return nil, err
	}
	d, err := utils.RandomPositiveInt(curveN)
	if err != nil {
		return nil, err
	}
	D := ecpointgrouplaw.ScalarBaseMult(curve, d)
	msgD, err := D.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	E := ecpointgrouplaw.ScalarBaseMult(curve, e)
	msgE, err := E.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	YPoint := ecpointgrouplaw.ScalarBaseMult(curve, share)
	msgY, err := YPoint.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	// Build and add self round1 message
	round1Msg := &Message{
		Id:   selfId,
		Type: Type_Round1,
		Body: &Message_Round1{
			Round1: &BodyRound1{
				D:  msgD,
				E:  msgE,
				SG: msgY,
			},
		},
	}
	r := &round1{
		threshold: threshold,
		message:   message,
		share:     share,
		pubKey:    pubKey,
		curveN:    curveN,

		ownbk: ownbk,

		peerManager: peerManager,
		peerNum:     peerManager.NumPeers(),
		nodes:       nodes,

		e:         e,
		d:         d,
		Y:         YPoint,
		round1Msg: round1Msg,
	}
	err = r.HandleMessage(log.New(), round1Msg)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (p *round1) MessageType() types.MessageType {
	return types.MessageType(Type_Round1)
}

func (p *round1) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round1) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.nodes[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round1) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.nodes[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}
	msgBody := msg.GetRound1()
	var err error
	peer.D, err = msgBody.D.ToPoint()
	if err != nil {
		logger.Debug("Failed ot ToPoint", "err", err)
		return err
	}
	peer.E, err = msgBody.E.ToPoint()
	if err != nil {
		logger.Debug("Failed ot ToPoint", "err", err)
		return err
	}

	return peer.AddMessage(msg)
}

func (p *round1) Finalize(logger log.Logger) (types.Handler, error) {
	// Build B/c/R
	identify := ecpointgrouplaw.NewIdentity(p.pubKey.GetCurve())
	R := identify.Copy()
	var B []byte
	// Get ordered nodes
	nodes := p.getOrderedNodes()
	for _, node := range nodes {
		msgBody := node.GetMessage(types.MessageType(Type_Round1)).(*Message).GetRound1()
		x := node.bk.GetX().Bytes()
		tempsG, err := msgBody.SG.ToPoint()
		if err != nil {
			logger.Debug("Failed ot ToPoint", "err", err)
			return nil, err
		}
		node.Y = tempsG
		B = append(B, computeB(x, node.D, node.E)...)
	}

	for _, node := range nodes {
		x := node.bk.GetX().Bytes()
		ell, err := computeElli(x, node.E, p.message, B, p.curveN)
		if err != nil {
			logger.Debug("Failed ot computeElli", "err", err)
			return nil, err
		}
		node.ell = ell
		// Compute ell_i*E_i+D_i
		Ri, err := computeRi(node.D, node.E, ell)
		if err != nil {
			logger.Debug("Failed ot computeRi", "err", err)
			return nil, err
		}
		node.ri = Ri
		R, err = R.Add(Ri)
		if err != nil {
			logger.Debug("Failed ot Add", "err", err)
			return nil, err
		}
	}
	if R.Equal(identify) {
		return nil, ErrTrivialSignature
	}
	p.c = SHAPoints(p.pubKey, R, p.message)
	p.r = R

	// Compute own si = di+ ei*li + c bi xi
	selfNode := p.nodes[p.peerManager.SelfID()]
	s := new(big.Int).Mul(p.e, selfNode.ell)
	temp := new(big.Int).Mul(p.c, selfNode.coBk)
	temp = temp.Mul(temp, p.share)
	s.Add(s, temp)
	s.Add(s, p.d)
	s.Mod(s, p.curveN)

	// Broadcast round2 message
	round2Msg := &Message{
		Id:   p.peerManager.SelfID(),
		Type: Type_Round2,
		Body: &Message_Round2{
			Round2: &BodyRound2{
				Si: s.Bytes(),
			},
		},
	}
	h, err := newRound2(p)
	if err != nil {
		return nil, err
	}
	err = h.HandleMessage(logger, round2Msg)
	if err != nil {
		logger.Debug("Failed ot AddMessage", "err", err)
		return nil, err
	}
	cggmp.Broadcast(p.peerManager, round2Msg)
	return h, nil
}

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}

func SHAPoints(pubKey, R *ecpointgrouplaw.ECPoint, message []byte) *big.Int {
	encodedR := ecpointEncoding(R)
	encodedPubKey := ecpointEncoding(pubKey)
	h := sha512.New()
	h.Write(encodedR[:])

	h.Write(encodedPubKey[:])
	h.Write(message)
	digest := h.Sum(nil)
	result := new(big.Int).SetBytes(utils.ReverseByte(digest))
	return result.Mod(result, R.GetCurve().Params().N)
}

func ecpointEncoding(pt *ecpointgrouplaw.ECPoint) *[32]byte {
	var result, X, Y [32]byte
	var x, y edwards25519.FieldElement
	if pt.Equal(ecpointgrouplaw.NewIdentity(pt.GetCurve())) {
		// TODO: We need to check this
		Y[0] = 1
	} else {
		tempX := pt.GetX().Bytes()
		tempY := pt.GetY().Bytes()

		for i := 0; i < len(tempX); i++ {
			index := len(tempX) - 1 - i
			X[index] = tempX[i]
		}
		for i := 0; i < len(tempY); i++ {
			index := len(tempY) - 1 - i
			Y[index] = tempY[i]
		}
	}
	edwards25519.FeFromBytes(&x, &X)
	edwards25519.FeFromBytes(&y, &Y)
	edwards25519.FeToBytes(&result, &y)
	result[31] ^= edwards25519.FeIsNegative(&x) << 7
	return &result
}

// Get xi,Di,Ei,.......
func computeB(x []byte, D, E *ecpointgrouplaw.ECPoint) []byte {
	var result []byte
	separationSign := []byte(",")
	result = append(result, x...)
	result = append(result, separationSign...)
	result = append(result, D.GetX().Bytes()...)
	result = append(result, separationSign...)
	result = append(result, E.GetY().Bytes()...)
	result = append(result, separationSign...)
	return result
}

func computeRi(D, E *ecpointgrouplaw.ECPoint, ell *big.Int) (*ecpointgrouplaw.ECPoint, error) {
	// Compute ell_i*E_i+D_i
	temp, err := E.ScalarMult(ell).Add(D)
	if err != nil {
		return nil, err
	}
	return temp, nil
}

func computeElli(x []byte, E *ecpointgrouplaw.ECPoint, message []byte, B []byte, fieldOrder *big.Int) (*big.Int, error) {
	temp, err := utils.HashProtosToInt(x, &any.Any{
		Value: message,
	}, &any.Any{
		Value: B,
	})
	if err != nil {
		return nil, err
	}
	tempMod := new(big.Int).Mod(temp, bit254)
	if tempMod.Cmp(fieldOrder) >= 0 {
		upBd := maxRetry - 2
		for j := 0; j < maxRetry; j++ {
			if j > upBd {
				return nil, ErrExceedMaxRetry
			}
			temp, err = utils.HashProtosToInt(temp.Bytes(), &any.Any{
				Value: temp.Bytes(),
			}, &any.Any{
				Value: B,
			})
			tempMod = new(big.Int).Mod(temp, bit254)
			if err != nil {
				return nil, err
			}
			if tempMod.Cmp(fieldOrder) < 0 {
				return temp, nil
			}
		}
	}
	return temp, nil
}

func (p *round1) getOrderedNodes() peers {
	var ps peers
	for _, n := range p.nodes {
		ps = append(ps, n)
	}

	sort.Sort(ps)
	return ps
}
