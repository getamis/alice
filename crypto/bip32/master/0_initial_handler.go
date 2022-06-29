// Copyright © 2021 AMIS Technologies
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

package master

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/bip32"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/circuit"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/ot"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"google.golang.org/protobuf/proto"
)

const (
	SeedLength = 32
	Threshold  = 2

	otherInfoBitStr = "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000010000000000010001000000000001000001010001010000000000000100010100000101000000010001010101000100000100000100010101010101010100010101000101010000000000000001000100000001000001000101010100010001000101000001010100000101010001010001010100010001000100010101000100010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000000001010100010100010100000100010100010100010001000100000100000000000001000001010100000101000001010101010101010100010000000000010000010000010000000101000101010100010100000101000000010101010001000100010001000101000101010000000101010101000101010101010001010101000100000101000101000101000001000001000101010100010100000001000100000001010001000000000101010001000001000100000001000100000000000100010001000100000101000101000100000101010000000100010100000101010001010101000001010000000101000001010101000101010101010101000001000100010000010000000000010001010001000001010101010100000100000000000100010100010100000000010000010000010100000101010001000101010000010100000100000101000000000100010100000001010101000101010101010001000001010101000001000101000000010001010100010100010001010100000101000000000100000000010000000100000101010001010000000100010100000000010101000100000100010000010000000101010100010100000101010000000001010000000000010100000000000101000000000001000001010001000000010001010101000100010001000000010101000100000101010001010000010100000100010100010000010100010001010000000101010101000000000001010000000000000101010001000101000101000101010100000100010000010001010001010001000001010001010101000100000000010100000101010100000001000001000000000000000000000100010000000000010101010000000101010100010100000000000100000001010101010000000001010000000001010001010000010100010001000001000101000001000101000000010101010101010000010100000100000001010101000001010001010101000101000001000100010001000000010101010100000000010100000001000100000101000001000101000001010001000100000101000000000000010100000001010000010100000101010100010100010000000000000100000100010000000001000001000000000100000101000100010101010001000000000100000100000001000101000100010101010000010001010100010101010101010001010100000000000101010101000101000000000000000001000001010101010100000101010100010001000100000001010101000100000000010001010100010101000101010100010100010101000001000101010001000001000000000100000000010100010001010100010101010000010000010001010101000101010001"
)

type parseResultFunc func(initialBody *BodyInitial, ownResult [][]byte) [][]byte
type computeOwnSeedBits func(ownSeed []uint8, randomValue *big.Int) []uint8

type initial struct {
	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
	selfId      string

	bk              *birkhoffinterpolation.BkParameter
	bks             birkhoffinterpolation.BkParameters
	sid             []byte
	garcircuit      *circuit.GarbleCircuit
	otExtSender     *ot.OtExtSender
	seedBits        []uint8
	seed            []uint8
	randomSeed      *big.Int
	parseResultFunc parseResultFunc
	initialMessage  *Message

	// updated after we received initial message
	otExtReceiver *ot.OtExtReceiver
}

var (
	otherInfoBit, _ = hex.DecodeString(otherInfoBitStr)
	curve           = elliptic.Secp256k1()
	secp256k1N      = curve.Params().N
	big2Inver, _    = new(big.Int).SetString("57896044618658097711785492504343953926418782139537452191302581570759080747169", 10)

	// alice
	aliceParseFunc = func(initialBody *BodyInitial, ownResult [][]byte) [][]byte {
		return append(append(ownResult, initialBody.GarcirMsg.X...), initialBody.OtherInfoWire...)
	}
	aliceComputeOwnSeedBitsFunc = func(ownSeed []uint8, randomValue *big.Int) []uint8 {
		randomValueBit := make([]uint8, 512)
		for i := 0; i < randomValue.BitLen(); i++ {
			randomValueBit[i] = uint8(randomValue.Bit(i))
		}
		return append(ownSeed, randomValueBit...)
	}
	newAliceMasterKey = newMasterKeyFunc(0, 768, 1024, aliceComputeOwnSeedBitsFunc, aliceParseFunc)

	// bob
	bobParseFunc = func(initialBody *BodyInitial, ownResult [][]byte) [][]byte {
		return append(append(initialBody.GarcirMsg.X, ownResult...), initialBody.OtherInfoWire...)
	}
	bobComputeOwnSeedBitsFunc = func(ownSeed []uint8, randomValue *big.Int) []uint8 {
		randomValueBit := make([]uint8, 512)
		for i := 0; i < randomValue.BitLen(); i++ {
			randomValueBit[i] = uint8(randomValue.Bit(i))
		}
		return append(randomValueBit, ownSeed...)
	}
	newBobMasterKey = newMasterKeyFunc(256, 0, 256, bobComputeOwnSeedBitsFunc, bobParseFunc)

	ErrPeerNotFound = errors.New("peer message not found")
	ErrInvalidSeed  = errors.New("invalid seed")
)

func newMasterKeyFunc(startIndex int, garbleStart int, garbleEnd int, computeFunc computeOwnSeedBits, parseFunc parseResultFunc) func(peerManager types.PeerManager, sid []uint8, seed []uint8, rank uint32, function string) (*initial, error) {
	return func(peerManager types.PeerManager, sid []uint8, seed []uint8, rank uint32, path string) (*initial, error) {
		cir, err := circuit.LoadBristol(path)
		if err != nil {
			return nil, err
		}

		if len(seed) != SeedLength {
			return nil, ErrInvalidSeed
		}

		// Random x and build bk
		x, err := utils.RandomPositiveInt(secp256k1N)
		if err != nil {
			return nil, err
		}
		bk := birkhoffinterpolation.NewBkParameter(x, rank)
		randomSeed, err := utils.RandomInt(secp256k1N)
		if err != nil {
			return nil, err
		}

		seedBits := utils.BytesToBits(seed)
		garcir, garMsg, err := cir.Garbled(bip32.Kappa, computeFunc(seedBits, randomSeed), circuit.EncryptFunc(startIndex))
		if err != nil {
			return nil, err
		}
		a0, a1 := garcir.GenerateGarbleWire(garbleStart, garbleEnd)
		otExtS, err := ot.NewExtSender(sid, bip32.Kappa, a0, a1)
		if err != nil {
			return nil, err
		}
		peerNum := peerManager.NumPeers()
		peers := make(map[string]*peer, peerNum)
		for _, id := range peerManager.PeerIDs() {
			peers[id] = newPeer(id)
		}
		return &initial{
			peerManager: peerManager,
			peerNum:     peerNum,
			peers:       peers,
			selfId:      peerManager.SelfID(),

			bk:              bk,
			sid:             sid,
			garcircuit:      garcir,
			otExtSender:     otExtS,
			seedBits:        seedBits,
			seed:            seed,
			randomSeed:      randomSeed,
			parseResultFunc: parseFunc,
			initialMessage: &Message{
				Type: Type_Initial,
				Id:   peerManager.SelfID(),
				Body: &Message_Initial{
					Initial: &BodyInitial{
						OtRecMsg:      otExtS.GetReceiverMessage(),
						GarcirMsg:     garMsg,
						OtherInfoWire: garcir.Encrypt(1024, otherInfoBit),
						Bk:            bk.ToMessage(),
					},
				},
			},
		}, nil
	}
}

func (s *initial) MessageType() types.MessageType {
	return types.MessageType(Type_Initial)
}

func (s *initial) GetRequiredMessageCount() uint32 {
	return s.peerManager.NumPeers()
}

func (s *initial) IsHandled(logger log.Logger, id string) bool {
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.GetMessage(s.MessageType()) != nil
}

func (s *initial) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := s.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return ErrPeerNotFound
	}

	body := msg.GetInitial()

	// Validate bk
	bk, err := body.GetBk().ToBk(secp256k1N)
	if err != nil {
		logger.Warn("Failed to get bk", "err", err)
		return err
	}

	peer.bk = bk
	s.bks = []*birkhoffinterpolation.BkParameter{
		s.bk,
		bk,
	}
	err = s.bks.CheckValid(Threshold, secp256k1N)
	if err != nil {
		logger.Warn("Invalid bks", "err", err)
		return err
	}

	// Build ot receiver
	otExtR, err := ot.NewExtReceiver(s.sid, s.seedBits, body.GetOtRecMsg())
	if err != nil {
		logger.Warn("Failed to new ot ext receiver", "err", err)
		return err
	}
	s.otExtReceiver = otExtR
	s.peerManager.MustSend(id, &Message{
		Type: Type_OtReceiver,
		Id:   s.selfId,
		Body: &Message_OtReceiver{
			OtReceiver: &BodyOtReceiver{
				OtExtReceiveMsg: otExtR.GetOtExtReceiveMessage(),
			},
		},
	})
	return peer.AddMessage(msg)
}

func (s *initial) Finalize(logger log.Logger) (types.Handler, error) {
	return newOtReceiver(s), nil
}

func (s *initial) broadcast(msg proto.Message) {
	for id := range s.peers {
		s.peerManager.MustSend(id, msg)
	}
}

func (s *initial) GetFirstMessage() *Message {
	return s.initialMessage
}

func getMessage(msg types.Message) *Message {
	return msg.(*Message)
}
