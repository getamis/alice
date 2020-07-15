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

package newpeer

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/addshare"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("peer handler, negative cases", func() {
	var (
		ph     *peerHandler
		peerID = "peer-id"
	)

	BeforeEach(func() {
		ph = &peerHandler{
			peers: map[string]*peer{},
		}
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(ph.IsHandled(log.Discard(), peerID)).Should(BeFalse())
		})

		It("message is handled before", func() {
			ph.peers[peerID] = &peer{}
			Expect(ph.IsHandled(log.Discard(), peerID)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			Expect(ph.IsHandled(log.Discard(), peerID)).Should(BeFalse())
		})
	})

	Context("HandleMessage/Finalize", func() {
		var (
			err         error
			threshold   uint32
			oldPeerBk   *birkhoffinterpolation.BkParameter
			pubkeyMsg   *ecpointgrouplaw.EcPointMessage
			siGProofMsg *zkproof.SchnorrProofMessage
		)

		BeforeEach(func() {
			threshold = uint32(0)
			oldPeerBk = birkhoffinterpolation.NewBkParameter(big.NewInt(0), uint32(0))
			pubkey := ecpointgrouplaw.NewBase(btcec.S256()).ScalarMult(big.NewInt(2))
			pubkeyMsg, err = pubkey.ToEcPointMessage()
			Expect(err).Should(BeNil())
			siGProofMsg, err = zkproof.NewBaseSchorrMessage(btcec.S256(), big.NewInt(5))
			Expect(err).Should(BeNil())

			ph.threshold = threshold
			ph.pubkey = pubkey
		})

		It("inconsistent threshold", func() {
			invalidThreshold := uint32(1)
			msg := &addshare.Message{
				Type: addshare.Type_OldPeer,
				Id:   peerID,
				Body: &addshare.Message_OldPeer{
					OldPeer: &addshare.BodyOldPeer{
						Bk:          oldPeerBk.ToMessage(),
						SiGProofMsg: siGProofMsg,
						Pubkey:      pubkeyMsg,
						Threshold:   invalidThreshold,
					},
				},
			}
			err := ph.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(tss.ErrInconsistentThreshold))
		})

		It("fails to get public key", func() {
			msg := &addshare.Message{
				Type: addshare.Type_OldPeer,
				Id:   peerID,
				Body: &addshare.Message_OldPeer{
					OldPeer: &addshare.BodyOldPeer{
						Bk:          oldPeerBk.ToMessage(),
						SiGProofMsg: siGProofMsg,
						Pubkey:      nil,
						Threshold:   threshold,
					},
				},
			}
			err = ph.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
		})

		It("inconsistent public key", func() {
			invalidPubkey := ecpointgrouplaw.NewBase(btcec.S256()).ScalarMult(big.NewInt(3))
			invalidPubkeyMsg, err := invalidPubkey.ToEcPointMessage()
			Expect(err).Should(BeNil())
			msg := &addshare.Message{
				Type: addshare.Type_OldPeer,
				Id:   peerID,
				Body: &addshare.Message_OldPeer{
					OldPeer: &addshare.BodyOldPeer{
						Bk:          oldPeerBk.ToMessage(),
						SiGProofMsg: siGProofMsg,
						Pubkey:      invalidPubkeyMsg,
						Threshold:   threshold,
					},
				},
			}
			err = ph.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(tss.ErrInconsistentPubKey))
		})

		It("fails to get siG", func() {
			invalidSiGProofMsg := &zkproof.SchnorrProofMessage{}
			msg := &addshare.Message{
				Type: addshare.Type_OldPeer,
				Id:   peerID,
				Body: &addshare.Message_OldPeer{
					OldPeer: &addshare.BodyOldPeer{
						Bk:          oldPeerBk.ToMessage(),
						SiGProofMsg: invalidSiGProofMsg,
						Pubkey:      pubkeyMsg,
						Threshold:   threshold,
					},
				},
			}
			err = ph.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
		})

		It("fails to verify siG", func() {
			v, err := ecpointgrouplaw.NewIdentity(btcec.S256()).ToEcPointMessage()
			Expect(err).Should(BeNil())
			invalidSiGProofMsg := &zkproof.SchnorrProofMessage{
				V: v,
			}
			msg := &addshare.Message{
				Type: addshare.Type_OldPeer,
				Id:   peerID,
				Body: &addshare.Message_OldPeer{
					OldPeer: &addshare.BodyOldPeer{
						Bk:          oldPeerBk.ToMessage(),
						SiGProofMsg: invalidSiGProofMsg,
						Pubkey:      pubkeyMsg,
						Threshold:   threshold,
					},
				},
			}
			err = ph.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
		})

		It("fails to validate the public key", func() {
			siG, err := siGProofMsg.V.ToPoint()
			Expect(err).Should(BeNil())
			ph.peerNum = uint32(1)
			ph.peers[peerID] = &peer{
				peer: &peerData{
					bk:  oldPeerBk,
					siG: siG,
				},
			}
			h, err := ph.Finalize(log.Discard())
			Expect(err).ShouldNot(BeNil())
			Expect(h).Should(BeNil())
		})
	})
})
