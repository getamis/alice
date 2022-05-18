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

package oldpeer

import (
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/addshare"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("compute handler, negative cases", func() {
	var (
		ch     *computeHandler
		peerID = "peer-id"
	)

	BeforeEach(func() {
		ch = &computeHandler{
			peerHandler: &peerHandler{
				peers: map[string]*peer{},
			},
		}
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(ch.IsHandled(log.Discard(), peerID)).Should(BeFalse())
		})

		It("message is handled before", func() {
			ch.peers[peerID] = &peer{
				compute: &computeData{},
			}
			Expect(ch.IsHandled(log.Discard(), peerID)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			ch.peers[peerID] = &peer{}
			Expect(ch.IsHandled(log.Discard(), peerID)).Should(BeFalse())
		})
	})

	Context("HandleMessage", func() {
		var (
			err         error
			pubkey      *ecpointgrouplaw.ECPoint
			siGProofMsg *zkproof.SchnorrProofMessage
		)

		BeforeEach(func() {
			siGProofMsg, err = zkproof.NewBaseSchorrMessage(elliptic.Secp256k1(), big.NewInt(5))
			Expect(err).Should(BeNil())
			pubkey = ecpointgrouplaw.NewBase(elliptic.Secp256k1()).ScalarMult(big.NewInt(2))

			ch.pubkey = pubkey
			ch.fieldOrder = pubkey.GetCurve().Params().N
			ch.peers[peerID] = newPeer(peerID)
		})

		It("peer not found", func() {
			msg := &addshare.Message{
				Type: addshare.Type_Compute,
				Id:   "invalid-peer",
				Body: &addshare.Message_Compute{
					Compute: &addshare.BodyCompute{
						Delta:       big.NewInt(10).Bytes(),
						SiGProofMsg: siGProofMsg,
					},
				},
			}
			err := ch.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(tss.ErrPeerNotFound))
		})

		It("fails with invalid delta value", func() {
			fieldOrder := pubkey.GetCurve().Params().N
			invalidDelta := new(big.Int).Add(fieldOrder, big.NewInt(1))
			msg := &addshare.Message{
				Type: addshare.Type_Compute,
				Id:   peerID,
				Body: &addshare.Message_Compute{
					Compute: &addshare.BodyCompute{
						Delta:       invalidDelta.Bytes(),
						SiGProofMsg: siGProofMsg,
					},
				},
			}
			err := ch.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(utils.ErrNotInRange))
		})

		It("fails to get point", func() {
			invalidSiGProofMsg := &zkproof.SchnorrProofMessage{}
			msg := &addshare.Message{
				Type: addshare.Type_Compute,
				Id:   peerID,
				Body: &addshare.Message_Compute{
					Compute: &addshare.BodyCompute{
						Delta:       big.NewInt(10).Bytes(),
						SiGProofMsg: invalidSiGProofMsg,
					},
				},
			}
			err := ch.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
		})

		It("fails to verify Schorr proof", func() {
			v, err := ecpointgrouplaw.NewIdentity(elliptic.Secp256k1()).ToEcPointMessage()
			Expect(err).Should(BeNil())
			invalidSiGProofMsg := &zkproof.SchnorrProofMessage{
				V: v,
			}
			msg := &addshare.Message{
				Type: addshare.Type_Compute,
				Id:   peerID,
				Body: &addshare.Message_Compute{
					Compute: &addshare.BodyCompute{
						Delta:       big.NewInt(10).Bytes(),
						SiGProofMsg: invalidSiGProofMsg,
					},
				},
			}
			err = ch.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
		})
	})
})
