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

package child

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/bip32"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/circuit"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/ot"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
)

const (
	PaillierLength = 2048
)

type parseResultFunc func(initialBody *BodyInitial, ownResult [][]byte) [][]byte
type hashFunc func(sid []byte, wv [][]byte, evaluation [][]byte) []byte

type initial struct {
	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
	selfId      string

	sm              *shareManager
	sid             []byte
	childIndex      uint32
	garcircuit      *circuit.GarbleCircuit
	otExtSender     *ot.OtExtSender
	share           *big.Int
	shareG          *ecpointgrouplaw.ECPoint
	shareBits       []uint8
	initialMessage  *Message
	homoKey         *paillier.Paillier
	parseResultFunc parseResultFunc
	hashFunc        hashFunc
}

var (
	curve      elliptic.Curve = elliptic.Secp256k1()
	secp256k1N                = curve.Params().N

	// alice
	aliceParseFunc = func(initialBody *BodyInitial, ownResult [][]byte) [][]byte {
		return append(append(ownResult, initialBody.GarcirMsg.X...), initialBody.OtherInfoWire...)
	}
	aliceHashFunc = func(sid []byte, wv [][]byte, evaluation [][]byte) []byte {
		inputData := make([]byte, len(sid))
		copy(inputData, sid)
		inputData = append(inputData, byte(','))
		for _, w := range wv {
			inputData = append(inputData, w...)
		}
		inputData = append(inputData, byte(','))
		for _, e := range evaluation {
			inputData = append(inputData, e...)
		}
		bs := blake2b.Sum256(inputData)
		return bs[:]
	}
	newAliceChildKey = newChildKeyFunc(0, 512, 1024, aliceParseFunc, aliceHashFunc)

	// bob
	bobParseFunc = func(initialBody *BodyInitial, ownResult [][]byte) [][]byte {
		return append(append(initialBody.GarcirMsg.X, ownResult...), initialBody.OtherInfoWire...)
	}
	bobHashFunc = func(sid []byte, wv [][]byte, evaluation [][]byte) []byte {
		inputData := make([]byte, len(sid))
		copy(inputData, sid)
		inputData = append(inputData, byte(','))
		for _, e := range evaluation {
			inputData = append(inputData, e...)
		}
		inputData = append(inputData, byte(','))
		for _, w := range wv {
			inputData = append(inputData, w...)
		}
		bs := blake2b.Sum256(inputData)
		return bs[:]
	}
	newBobChildKey = newChildKeyFunc(512, 0, 512, bobParseFunc, bobHashFunc)

	ErrPeerNotFound = errors.New("peer message not found")
	ErrInvalidSeed  = errors.New("invalid seed")
)

func newChildKeyFunc(startIndex int, garbleStart int, garbleEnd int, parseResultFunc parseResultFunc, hashFunc hashFunc) func(peerManager types.PeerManager, share *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, sid []uint8, path string, chainCode []byte, depth uint8, childIndex uint32, pubKey *ecpointgrouplaw.ECPoint) (*initial, error) {
	return func(peerManager types.PeerManager, share *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, sid []uint8, path string, chainCode []byte, depth uint8, childIndex uint32, pubKey *ecpointgrouplaw.ECPoint) (*initial, error) {
		cir, err := circuit.LoadBristol(path)
		if err != nil {
			return nil, err
		}

		peerNum := peerManager.NumPeers()
		selfId := peerManager.SelfID()

		// Consider bk coefficients
		bbks := make(birkhoffinterpolation.BkParameters, len(bks))
		bbks[0] = bks[selfId]
		i := 1
		for id, bk := range bks {
			if id != selfId {
				bbks[i] = bk
				i++
			}
		}
		cos, err := bbks.ComputeBkCoefficient(peerNum+1, secp256k1N)
		if err != nil {
			return nil, err
		}
		share = new(big.Int).Mul(share, cos[0])
		share = new(big.Int).Mod(share, secp256k1N)

		// Build share manager
		sm, err := NewShareManager(share, pubKey, chainCode, depth)
		if err != nil {
			return nil, err
		}
		firstState, err := sm.ComputeHardenKeyPrepareData()
		if err != nil {
			return nil, err
		}
		otherInfoBit, err := computePaddingInput(childIndex, firstState)
		if err != nil {
			return nil, err
		}

		shareBits := make([]uint8, 512)
		for i := 0; i < len(shareBits); i++ {
			shareBits[i] = uint8(share.Bit(i))
		}
		garcir, garMsg, err := cir.Garbled(bip32.Kappa, shareBits, circuit.EncryptFunc(startIndex))
		if err != nil {
			return nil, err
		}
		a0, a1 := garcir.GenerateGarbleWire(garbleStart, garbleEnd)
		otExtS, err := ot.NewExtSender(sid, bip32.Kappa, a0, a1)
		if err != nil {
			return nil, err
		}

		homoKey, err := paillier.NewPaillier(PaillierLength)
		if err != nil {
			return nil, err
		}

		shareGProof, err := zkproof.NewBaseSchorrMessage(curve, share)
		if err != nil {
			return nil, err
		}

		peers := make(map[string]*peer, peerNum)
		for _, id := range peerManager.PeerIDs() {
			peers[id] = newPeer(id)
		}
		return &initial{
			peerManager:     peerManager,
			peerNum:         peerNum,
			peers:           peers,
			selfId:          selfId,
			parseResultFunc: parseResultFunc,
			hashFunc:        hashFunc,

			sm:          sm,
			sid:         sid,
			childIndex:  childIndex,
			garcircuit:  garcir,
			otExtSender: otExtS,
			share:       share,
			shareG:      ecpointgrouplaw.ScalarBaseMult(curve, share),
			shareBits:   shareBits,
			homoKey:     homoKey,
			initialMessage: &Message{
				Type: Type_Initial,
				Id:   peerManager.SelfID(),
				Body: &Message_Initial{
					Initial: &BodyInitial{
						OtRecMsg:       otExtS.GetReceiverMessage(),
						GarcirMsg:      garMsg,
						OtherInfoWire:  garcir.Encrypt(1024, otherInfoBit),
						PubKey:         homoKey.ToPubKeyBytes(),
						PubKeyN:        homoKey.GetN().Bytes(),
						ShareGProofMsg: shareGProof,
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

	// Build ot receiver
	pubKey, err := s.homoKey.NewPubKeyFromBytes(body.PubKey)
	if err != nil {
		logger.Warn("Failed to new public key", "err", err)
		return err
	}
	peer.pubkey = pubKey
	peer.pubkeyN = new(big.Int).SetBytes(body.PubKeyN)
	otExtR, err := ot.NewExtReceiver(s.sid, s.shareBits, body.GetOtRecMsg())
	if err != nil {
		logger.Warn("Failed to new ot ext receiver", "err", err)
		return err
	}
	peer.otExtReceiver = otExtR
	shareGMsg := body.GetShareGProofMsg()
	err = shareGMsg.Verify(ecpointgrouplaw.NewBase(curve))
	if err != nil {
		logger.Warn("Failed to verify Schorr proof", "err", err)
		return err
	}
	shareG, err := shareGMsg.V.ToPoint()
	if err != nil {
		logger.Warn("Failed to get ec point", "err", err)
		return err
	}
	got, err := s.shareG.Add(shareG)
	if err != nil {
		logger.Warn("Failed to add points", "err", err)
		return err
	}
	if !s.sm.publicKey.Equal(got) {
		logger.Warn("Inconsistent public key", "got", got, "expected", s.sm.publicKey)
		return ErrVerifyFailure
	}
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

func computePaddingInput(childIndex uint32, firstState []uint64) ([]uint8, error) {
	otherInfo := make([]uint8, 512)
	for i := 0; i < 512; i++ {
		otherInfo[i] = uint8(secp256k1N.Bit(i))
	}
	indexKey := make([]uint8, 32)
	bigIndexKey := new(big.Int).SetUint64(uint64(childIndex))
	for i := 0; i < 32; i++ {
		indexKey[31-i] = uint8(bigIndexKey.Bit(i))
	}
	zeroShaPadding := make([]uint8, 717)
	zeroShaPadding[0] = 1
	countValue := make([]uint8, 11)
	countValue[0] = 1
	countValue[2] = 1
	countValue[5] = 1
	countValue[7] = 1
	zero := make([]uint8, 8)

	prestate, err := circuit.SetShaStateBristolInput(firstState)
	if err != nil {
		return nil, err
	}
	otherInfo = append(otherInfo, indexKey...)
	otherInfo = append(otherInfo, zeroShaPadding...)
	otherInfo = append(otherInfo, countValue...)
	otherInfo = append(otherInfo, zero...)
	otherInfo = append(otherInfo, prestate...)
	return otherInfo, nil
}
