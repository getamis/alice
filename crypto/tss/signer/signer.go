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

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

type FirstHandler interface {
	types.Handler

	GetFirstMessage() *Message
	GetPubKHandler() *pubkeyHandler
}

type Result struct {
	R *pt.ECPoint
	S *big.Int
}

// EthSignature returns the eth signature
// Use github.com/ethereum/go-ethereum/core/types.Transaction.WithSignature(signer, signatures)
// to get the signed transaction. Suggest to use types.Signer155.
func (r *Result) EthSignature() []byte {
	n := r.R.GetCurve().Params().N
	s := new(big.Int).Set(r.S)

	// 1. Modify s to 0 < s < N /2
	// ref: condition 283 in https://ethereum.github.io/yellowpaper/paper.pdf
	// 2. Calculate recovery id
	// https://ethereum.stackexchange.com/questions/42455/during-ecdsa-signing-how-do-i-generate-the-recovery-id
	id := r.R.GetY().Bit(0)
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s = new(big.Int).Neg(s)
		s = s.Add(n, s)
		id = id ^ 1
	}

	// The signature is 65 bytes, [R (32 bytes)|S (32 bytes)|recovery id (1 byte)]
	sig := make([]byte, 65)
	rBytes := r.R.GetX().Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	sBytes := s.Bytes()
	copy(sig[64-len(sBytes):64], sBytes)
	sig[64] = byte(id)
	return sig
}

type Signer struct {
	ph          FirstHandler
	peerManager types.PeerManager
	*message.MsgMain
}

func NewSigner(peerManager types.PeerManager, expectedPubkey *pt.ECPoint, homo homo.Crypto, secret *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte, listener types.StateChangedListener) (*Signer, error) {
	ph, err := newPubkeyHandler(expectedPubkey, peerManager, homo, secret, bks, msg, true)
	if err != nil {
		log.Debug("Failed to new a public key handler", "err", err)
		return nil, err
	}
	return newSigner(peerManager, listener, ph, types.MessageType(Type_Si))
}

func NewPasswordUserSigner(peerManager types.PeerManager, expectedPubkey *pt.ECPoint, homo homo.Crypto, password []byte, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte, listener types.StateChangedListener) (*Signer, error) {
	ph, err := newPasswordUserHandler(expectedPubkey, peerManager, homo, password, bks, msg)
	if err != nil {
		log.Debug("Failed to new a public key handler", "err", err)
		return nil, err
	}
	return newSigner(peerManager, listener, ph, types.MessageType(Type_Si), types.MessageType(Type_OPRFResponse))
}

func NewPasswordServerSigner(peerManager types.PeerManager, expectedPubkey *pt.ECPoint, homo homo.Crypto, k *big.Int, secret *big.Int, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte, listener types.StateChangedListener) (*Signer, error) {
	ph, err := newPasswordServerHandler(expectedPubkey, peerManager, homo, secret, k, bks, msg)
	if err != nil {
		log.Debug("Failed to new a public key handler", "err", err)
		return nil, err
	}
	return newSigner(peerManager, listener, ph, types.MessageType(Type_Si), types.MessageType(Type_OPRFRequest))
}

func newSigner(peerManager types.PeerManager, listener types.StateChangedListener, ph FirstHandler, msgs ...types.MessageType) (*Signer, error) {
	peerNum := peerManager.NumPeers()
	msgs = append(msgs,
		types.MessageType(Type_Pubkey),
		types.MessageType(Type_EncK),
		types.MessageType(Type_Mta),
		types.MessageType(Type_Delta),
		types.MessageType(Type_ProofAi),
		types.MessageType(Type_CommitViAi),
		types.MessageType(Type_DecommitViAi),
		types.MessageType(Type_CommitUiTi),
		types.MessageType(Type_DecommitUiTi))
	return &Signer{
		ph:          ph,
		peerManager: peerManager,
		MsgMain:     message.NewMsgMain(peerManager.SelfID(), peerNum, listener, ph, msgs...),
	}, nil
}
func (s *Signer) Start() {
	s.MsgMain.Start()

	msg := s.ph.GetFirstMessage()
	if msg != nil {
		message.Broadcast(s.peerManager, msg)
	}
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (s *Signer) GetResult() (*Result, error) {
	if s.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := s.GetHandler()
	rh, ok := h.(*siHandler)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	return &Result{
		R: rh.r.Copy(),
		S: new(big.Int).Set(rh.s),
	}, nil
}
