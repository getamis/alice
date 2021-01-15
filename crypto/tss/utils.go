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

package tss

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/sirius/log"
)

const (
	// For password cases, we only support 2-of-2 and rank 0 for now
	PasswordRank      = 0
	PasswordThreshold = 2
	PasswordN         = 2
)

var (
	ErrInvalidMsg                = errors.New("invalid message")
	ErrNotReady                  = errors.New("not ready")
	ErrPeerNotFound              = errors.New("peer message not found")
	ErrNotEnoughBKs              = errors.New("not enough Birkhoff coefficient")
	ErrSelfBKNotFound            = errors.New("self Birkhoff coefficient not found")
	ErrInvalidBK                 = errors.New("invalid Birkhoff coefficient")
	ErrInconsistentThreshold     = errors.New("inconsistent threshold")
	ErrInconsistentPeerNumAndBks = errors.New("inconsistent peer num and bks")
	ErrInconsistentPubKey        = errors.New("inconsistent public key")

	// ErrUnexpectedPublickey is returned if the public key is unexpected
	ErrUnexpectedPublickey = errors.New("unexpected public key")
)

func NewCommitterByPoint(p *pt.ECPoint) (*commitment.HashCommitmenter, error) {
	msg, err := p.ToEcPointMessage()
	if err != nil {
		log.Warn("Failed to convert to an ec point message", "err", err)
		return nil, err
	}

	return commitment.NewProtoHashCommitmenter(msg)
}

func GetPointFromHashCommitment(logger log.Logger, commit *commitment.HashCommitmentMessage, decommit *commitment.HashDecommitmentMessage) (*pt.ECPoint, error) {
	msg := &pt.EcPointMessage{}
	err := commit.DecommitToProto(decommit, msg)
	if err != nil {
		logger.Warn("Failed to decommit message", "err", err)
		return nil, err
	}
	point, err := msg.ToPoint()
	if err != nil {
		logger.Warn("Failed to convert to ec point", "err", err)
		return nil, err
	}
	return point, nil
}

func ValidatePublicKey(logger log.Logger, bks birkhoffinterpolation.BkParameters, sgs []*pt.ECPoint, threshold uint32, pubkey *pt.ECPoint) error {
	fieldOrder := pubkey.GetCurve().Params().N
	scalars, err := bks.ComputeBkCoefficient(threshold, fieldOrder)
	if err != nil {
		logger.Warn("Failed to compute", "err", err)
		return err
	}
	return ValidatePublicKeyWithBkCoefficients(logger, scalars, sgs, pubkey)
}

func ValidatePublicKeyWithBkCoefficients(logger log.Logger, scalars []*big.Int, sgs []*pt.ECPoint, pubkey *pt.ECPoint) error {
	gotPub, err := pt.ComputeLinearCombinationPoint(scalars, sgs)
	if err != nil {
		logger.Warn("Failed to calculate public", "err", err)
		return err
	}
	if !pubkey.Equal(gotPub) {
		logger.Warn("Inconsistent public key", "got", gotPub, "expected", pubkey)
		return ErrInconsistentPubKey
	}
	return nil
}

func Broadcast(peerManager types.PeerManager, message interface{}) {
	peers := peerManager.PeerIDs()
	for _, id := range peers {
		peerManager.MustSend(id, message)
	}
}

// ------------
// Below funcs are for testing
func GetTestID(id int) string {
	return fmt.Sprintf("id-%d", id)
}

func GetTestPeers(id int, lens int) []string {
	var peers []string
	for i := 0; i < lens; i++ {
		if i == id {
			continue
		}
		peers = append(peers, GetTestID(i))
	}
	return peers
}

func GetTestPeersByArray(id int, ids []int) []string {
	var peers []string
	for _, peerID := range ids {
		if peerID == id {
			continue
		}
		peers = append(peers, GetTestID(peerID))
	}
	return peers
}

type TestPeerManager struct {
	id       string
	peers    []string
	msgMains map[string]types.MessageMain
}

func NewTestPeerManager(id int, lens int) *TestPeerManager {
	return &TestPeerManager{
		id:       GetTestID(id),
		peers:    GetTestPeers(id, lens),
		msgMains: make(map[string]types.MessageMain),
	}
}

func NewTestPeerManagerWithPeers(id int, peers []string) *TestPeerManager {
	return &TestPeerManager{
		id:       GetTestID(id),
		peers:    peers,
		msgMains: make(map[string]types.MessageMain),
	}
}

func (p *TestPeerManager) Set(msgMains map[string]types.MessageMain) {
	p.msgMains = msgMains
}

func (p *TestPeerManager) NumPeers() uint32 {
	return uint32(len(p.peers))
}

func (p *TestPeerManager) SelfID() string {
	return p.id
}

func (p *TestPeerManager) PeerIDs() []string {
	return p.peers
}

// Only send if the msg main exists
func (p *TestPeerManager) MustSend(id string, message interface{}) {
	d, ok := p.msgMains[id]
	if !ok {
		return
	}
	msg := message.(types.Message)
	d.AddMessage(msg)
}

func IsWrongPasswordError(err error) bool {
	return err == ErrUnexpectedPublickey
}
