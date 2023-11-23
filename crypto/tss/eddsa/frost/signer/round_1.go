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
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"sort"

	"github.com/agl/ed25519/edwards25519"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/commitment"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/protobuf/proto"
)

const (
	// maxRetry defines the max retries to generate proof
	maxRetry = 300
)

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)

	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
	//ErrPeerNotFound is returned if peer message not found.
	ErrPeerNotFound = errors.New("peer message not found")
	//ErrTrivialSignature is returned if obtain trivial signature.
	ErrTrivialSignature = errors.New("obtain trivial signature")
	//ErrTrivialShaResult is returned if the output of SHAPoint is trivial.
	ErrTrivialShaResult = errors.New("the output of SHAPoint is trivial")
	//ErrNotSupportCurve is returned if the curve is not support.
	ErrNotSupportCurve = errors.New("if the curve is not support")
	//ErrTrivialPoint is returned if the point is trivial.
	ErrTrivialPoint = errors.New("the point is trivial")
	//ErrNotCorrectMessage is returned if the message is not correct.
	ErrNotCorrectMessage = errors.New("the message is not correct")
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

	round1Msg *Message

	// Results
	r *ecpointgrouplaw.ECPoint
	c *big.Int
}

func newRound1(pubKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, threshold uint32, share *big.Int, dkgResult *dkg.Result, message []byte) (*round1, error) {
	bks := dkgResult.Bks
	ys := dkgResult.Ys
	selfId := peerManager.SelfID()
	ownbk := bks[selfId]
	curve := pubKey.GetCurve()
	curveN := curve.Params().N
	bbks := make(birkhoffinterpolation.BkParameters, len(bks))
	nodes := make(map[string]*peer, peerManager.NumPeers()+1)
	i := 0
	for id, bk := range bks {
		bbks[i] = bk
		nodes[id] = newPeer(id, i, bk, ys[id])
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

	// Build and add self round1 message
	round1Msg := &Message{
		Id:   selfId,
		Type: Type_Round1,
		Body: &Message_Round1{
			Round1: &BodyRound1{
				D: msgD,
				E: msgE,
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
	var err error
	// Get ordered nodes
	nodes := p.getOrderedNodes()
	for _, node := range nodes {
		x := node.bk.GetX().Bytes()
		subBPart, err := computeB(x, node.D, node.E)
		if err != nil {
			return nil, err
		}
		B = append(B, subBPart...)
	}

	for _, node := range nodes {
		x := node.bk.GetX().Bytes()
		ell, err := computeRhoElli(x, node.E, p.message, B, p.curveN)
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
	p.c, err = SHAPoints(p.pubKey, R, p.message)

	if err != nil {
		return nil, err
	}
	p.r = R
	// Compute own zi = di+ ei*li + c bi xi
	selfNode := p.nodes[p.peerManager.SelfID()]
	share := new(big.Int).Set(p.share)
	p.d, p.e, share, err = computeDEShareTaproot(p.d, p.e, share, R, p.pubKey)
	if err != nil {
		return nil, err
	}
	z := new(big.Int).Mul(p.e, selfNode.ell)
	temp := new(big.Int).Mul(p.c, selfNode.coBk)
	temp = temp.Mul(temp, share)
	z.Add(z, temp)
	z.Add(z, p.d)
	z.Mod(z, p.curveN)
	// Broadcast round2 message
	round2Msg := &Message{
		Id:   p.peerManager.SelfID(),
		Type: Type_Round2,
		Body: &Message_Round2{
			Round2: &BodyRound2{
				Zi: z.Bytes(),
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

// Different curves for Schnorr signature has different rules.
func computeDEShareTaproot(d, e, s *big.Int, R, pubKey *ecpointgrouplaw.ECPoint) (*big.Int, *big.Int, *big.Int, error) {
	curve := R.GetCurve()
	switch curve {
	// Taproot verification
	case elliptic.Secp256k1():
		if !R.IsEvenY() {
			d, e = d.Sub(curve.Params().N, d), e.Sub(curve.Params().N, e)
		}
		if !pubKey.IsEvenY() {
			s = s.Sub(curve.Params().N, s)
		}
		return d, e, s, nil
	case elliptic.Ed25519():
		return d, e, s, nil
	}
	return nil, nil, nil, ErrNotSupportCurve
}

func SHAPoints(pubKey, R *ecpointgrouplaw.ECPoint, message []byte) (*big.Int, error) {
	curveType := pubKey.GetCurve()
	if R.IsIdentity() || pubKey.IsIdentity() {
		return nil, ErrTrivialPoint
	}
	switch curveType {
	case elliptic.Secp256k1():
		// e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n
		if len(message) != 32 {
			return nil, ErrNotCorrectMessage
		}
		hash := make([]byte, 0)
		hash = append(hash, utils.Bytes32(R.GetX())...)
		hash = append(hash, utils.Bytes32(pubKey.GetX())...)
		hash = append(hash, utils.Pad(message, 32)...)

		sha256Hash := sha256.Sum256([]byte("BIPSchnorr"))
		sha256HashInput := sha256Hash[:]
		sha256HashInput = append(sha256HashInput, sha256HashInput[:]...)
		sha256HashInput = append(sha256HashInput, hash...)
		digest := sha256.Sum256(sha256HashInput)
		result := new(big.Int).SetBytes(digest[:])

		result.Mod(result, R.GetCurve().Params().N)
		if result.Cmp(big0) == 0 {
			return nil, ErrTrivialShaResult
		}
		return result, nil

	case elliptic.Ed25519():
		encodedR, err := ecpointEncoding(R)
		if err != nil {
			return nil, err
		}
		encodedPubKey, err := ecpointEncoding(pubKey)
		if err != nil {
			return nil, err
		}

		h := sha512.New()
		h.Write(encodedR[:])

		h.Write(encodedPubKey[:])
		h.Write(message)
		digest := h.Sum(nil)
		result := new(big.Int).SetBytes(utils.ReverseByte(digest))
		result = result.Mod(result, R.GetCurve().Params().N)
		if result.Cmp(big0) == 0 {
			return nil, ErrTrivialShaResult
		}

		return result, nil
	}
	return nil, ErrNotSupportCurve
}

func ecpointEncoding(pt *ecpointgrouplaw.ECPoint) ([32]byte, error) {
	curveType := pt.GetCurve()
	nullSlice := [32]byte{}
	if pt.IsIdentity() {
		return nullSlice, ErrTrivialPoint
	}
	switch curveType {
	case elliptic.Secp256k1():
		return ([32]byte)(utils.Bytes32(pt.GetX())), nil
	case elliptic.Ed25519():
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
		return result, nil
	}
	return nullSlice, ErrNotSupportCurve
}

// Get xi,Di,Ei,.......
func computeB(x []byte, D, E *ecpointgrouplaw.ECPoint) ([]byte, error) {
	if !D.IsSameCurve(E) {
		return nil, ecpointgrouplaw.ErrDifferentCurve
	}
	encodingD, err := ecpointEncoding(D)
	if err != nil {
		return nil, err
	}

	encodingE, err := ecpointEncoding(E)
	if err != nil {
		return nil, err
	}
	bMsg := &BMessage{
		X: x,
		D: encodingD[:],
		E: encodingE[:],
	}
	result, err := proto.Marshal(bMsg)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func computeRi(D, E *ecpointgrouplaw.ECPoint, ell *big.Int) (*ecpointgrouplaw.ECPoint, error) {
	// Compute ell_i*E_i+D_i
	temp, err := E.ScalarMult(ell).Add(D)
	if err != nil {
		return nil, err
	}
	return temp, nil
}

func computeRhoElli(x []byte, E *ecpointgrouplaw.ECPoint, message []byte, B []byte, fieldOrder *big.Int) (*big.Int, error) {
	temp, err := utils.HashProtosToInt(x, &any.Any{
		Value: message,
	}, &any.Any{
		Value: B,
	})
	if err != nil {
		return nil, err
	}
	bitUppBd := new(big.Int).Lsh(big1, uint(E.GetCurve().Params().N.BitLen()))
	for j := 0; j < maxRetry; j++ {
		tempMod := new(big.Int).Mod(temp, bitUppBd)
		if utils.InRange(tempMod, big1, fieldOrder) == nil {
			return tempMod, nil
		}
		tempBytes := temp.Bytes()
		temp, err = utils.HashProtosToInt(tempBytes, &any.Any{
			Value: tempBytes,
		}, &any.Any{
			Value: B,
		})
		if err != nil {
			return nil, err
		}
	}
	return nil, ErrExceedMaxRetry
}

func (p *round1) getOrderedNodes() peers {
	var ps peers
	for _, n := range p.nodes {
		ps = append(ps, n)
	}

	sort.Sort(ps)
	return ps
}
