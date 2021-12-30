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

	"github.com/aisuosuo/alice/crypto/ecpointgrouplaw"
	"github.com/aisuosuo/alice/crypto/tss"
	"github.com/aisuosuo/alice/crypto/tss/addshare"
	"github.com/aisuosuo/alice/crypto/utils"
	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("result handler, negative cases", func() {
	var (
		rh     *resultHandler
		peerID = "peer-id"
	)

	BeforeEach(func() {
		rh = &resultHandler{
			peerHandler: &peerHandler{
				peers: map[string]*peer{},
			},
		}
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(rh.IsHandled(log.Discard(), peerID)).Should(BeFalse())
		})

		It("message is handled before", func() {
			rh.peers[peerID] = &peer{
				result: &resultData{},
			}
			Expect(rh.IsHandled(log.Discard(), peerID)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			rh.peers[peerID] = &peer{}
			Expect(rh.IsHandled(log.Discard(), peerID)).Should(BeFalse())
		})
	})

	Context("HandleMessage/Finalize", func() {
		var (
			threshold uint32
			pubkey    *ecpointgrouplaw.ECPoint
		)

		BeforeEach(func() {
			threshold = uint32(0)
			pubkey = ecpointgrouplaw.NewBase(btcec.S256()).ScalarMult(big.NewInt(2))

			rh.threshold = threshold
			rh.pubkey = pubkey
			rh.fieldOrder = pubkey.GetCurve().Params().N
		})

		It("fails with peer not found", func() {
			msg := &addshare.Message{
				Type: addshare.Type_Result,
				Id:   peerID,
				Body: &addshare.Message_Result{
					Result: &addshare.BodyResult{
						Delta: big.NewInt(10).Bytes(),
					},
				},
			}
			err := rh.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(tss.ErrPeerNotFound))
		})

		It("fails with invalid delta value", func() {
			rh.peers[peerID] = newPeer(peerID)
			fieldOrder := pubkey.GetCurve().Params().N
			invalidDelta := new(big.Int).Add(fieldOrder, big.NewInt(1))
			msg := &addshare.Message{
				Type: addshare.Type_Result,
				Id:   peerID,
				Body: &addshare.Message_Result{
					Result: &addshare.BodyResult{
						Delta: invalidDelta.Bytes(),
					},
				},
			}
			err := rh.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(utils.ErrNotInRange))
		})

		It("fails to validate the public key", func() {
			rh.peers[peerID] = &peer{
				result: &resultData{
					delta: big.NewInt(10),
				},
			}
			h, err := rh.Finalize(log.Discard())
			Expect(err).ShouldNot(BeNil())
			Expect(h).Should(BeNil())
		})
	})
})
