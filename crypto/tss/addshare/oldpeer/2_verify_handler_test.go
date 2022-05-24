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

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/addshare"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("verify handler, negative cases", func() {
	var (
		vh     *verifyHandler
		peerID = "peer-id"
	)

	BeforeEach(func() {
		vh = &verifyHandler{
			computeHandler: &computeHandler{
				peerHandler: &peerHandler{
					newPeer: newPeer(peerID),
				},
			},
		}
	})

	Context("IsHandled", func() {
		It("wrong peer", func() {
			Expect(vh.IsHandled(log.Discard(), "invalid-peer")).Should(BeFalse())
		})

		It("message is handled before", func() {
			vh.newPeer.verify = &verifyData{}
			Expect(vh.IsHandled(log.Discard(), peerID)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			Expect(vh.IsHandled(log.Discard(), peerID)).Should(BeFalse())
		})
	})

	Context("HandleMessage/Finalize", func() {
		var (
			pubkey      *ecpointgrouplaw.ECPoint
			siGProofMsg *zkproof.SchnorrProofMessage

			newBk  *birkhoffinterpolation.BkParameter
			selfBk *birkhoffinterpolation.BkParameter
		)

		BeforeEach(func() {
			curve := btcec.S256()
			pubkey = ecpointgrouplaw.NewBase(btcec.S256()).ScalarMult(big.NewInt(2))

			// self information
			selfRank := uint32(0)
			x, err := utils.RandomPositiveInt(curve.Params().N)
			Expect(err).Should(BeNil())
			selfBk = birkhoffinterpolation.NewBkParameter(x, selfRank)
			selfSiGProofMsg, err := zkproof.NewBaseSchorrMessage(btcec.S256(), big.NewInt(4))
			Expect(err).Should(BeNil())

			// new peer information
			newPeerRank := uint32(0)
			x, err = utils.RandomPositiveInt(curve.Params().N)
			Expect(err).Should(BeNil())
			newBk = birkhoffinterpolation.NewBkParameter(x, newPeerRank)
			siGProofMsg, err = zkproof.NewBaseSchorrMessage(btcec.S256(), big.NewInt(5))
			Expect(err).Should(BeNil())
			siG, err := siGProofMsg.V.ToPoint()
			Expect(err).Should(BeNil())

			vh.peerNum = 0
			vh.bk = selfBk
			vh.pubkey = pubkey
			vh.siGProofMsg = selfSiGProofMsg
			vh.peers = map[string]*peer{}
			vh.newPeer = newPeer(peerID)
			vh.newPeer.peer = &peerData{
				bk: newBk,
			}
			vh.newPeer.verify = &verifyData{
				siG:         siG,
				siGProofMsg: siGProofMsg,
			}
		})

		It("fails with request from wrong peer", func() {
			msg := &addshare.Message{
				Type: addshare.Type_Verify,
				Id:   "invalid-peer",
				Body: &addshare.Message_Verify{
					Verify: &addshare.BodyVerify{
						SiGProofMsg: siGProofMsg,
					},
				},
			}
			err := vh.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(tss.ErrInvalidMsg))
		})

		It("fails to get point", func() {
			invalidSiGProofMsg := &zkproof.SchnorrProofMessage{}
			msg := &addshare.Message{
				Type: addshare.Type_Verify,
				Id:   peerID,
				Body: &addshare.Message_Verify{
					Verify: &addshare.BodyVerify{
						SiGProofMsg: invalidSiGProofMsg,
					},
				},
			}
			err := vh.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
		})

		It("fails to verify Schorr proof", func() {
			v, err := ecpointgrouplaw.NewIdentity(btcec.S256()).ToEcPointMessage()
			Expect(err).Should(BeNil())
			invalidSiGProofMsg := &zkproof.SchnorrProofMessage{
				V: v,
			}
			msg := &addshare.Message{
				Type: addshare.Type_Verify,
				Id:   peerID,
				Body: &addshare.Message_Verify{
					Verify: &addshare.BodyVerify{
						SiGProofMsg: invalidSiGProofMsg,
					},
				},
			}
			err = vh.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
		})

		It("fails to get siG", func() {
			vh.siGProofMsg = &zkproof.SchnorrProofMessage{}
			h, err := vh.Finalize(log.Discard())
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidPoint))
			Expect(h).Should(BeNil())
		})

		It("fails to validate the public key", func() {
			h, err := vh.Finalize(log.Discard())
			Expect(err).ShouldNot(BeNil())
			Expect(h).Should(BeNil())
		})
	})
})
