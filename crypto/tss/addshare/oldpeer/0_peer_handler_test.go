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
	"crypto/elliptic"
	"math/big"

	"github.com/aisuosuo/alice/crypto/birkhoffinterpolation"
	"github.com/aisuosuo/alice/crypto/ecpointgrouplaw"
	"github.com/aisuosuo/alice/crypto/tss"
	"github.com/aisuosuo/alice/crypto/tss/addshare"
	"github.com/aisuosuo/alice/crypto/utils"
	"github.com/btcsuite/btcd/btcec"
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
			newPeer: newPeer(peerID),
		}
	})

	Context("IsHandled", func() {
		It("wrong peer", func() {
			Expect(ph.IsHandled(log.Discard(), "invalid-peer")).Should(BeFalse())
		})

		It("message is handled before", func() {
			ph.newPeer.peer = &peerData{}
			Expect(ph.IsHandled(log.Discard(), peerID)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			Expect(ph.IsHandled(log.Discard(), peerID)).Should(BeFalse())
		})
	})

	Context("HandleMessage/Finalize", func() {
		var (
			curve       elliptic.Curve
			newPeerRank uint32
			newBk       *birkhoffinterpolation.BkParameter
			selfBk      *birkhoffinterpolation.BkParameter
		)

		BeforeEach(func() {
			curve = btcec.S256()
			newPeerRank = uint32(0)
			selfRank := uint32(0)
			pubkey := ecpointgrouplaw.NewBase(btcec.S256()).ScalarMult(big.NewInt(2))
			x, err := utils.RandomPositiveInt(curve.Params().N)
			Expect(err).Should(BeNil())
			newBk = birkhoffinterpolation.NewBkParameter(x, newPeerRank)
			x, err = utils.RandomPositiveInt(curve.Params().N)
			Expect(err).Should(BeNil())
			selfBk = birkhoffinterpolation.NewBkParameter(x, selfRank)

			ph.bk = selfBk
			ph.pubkey = pubkey
			ph.fieldOrder = pubkey.GetCurve().Params().N
			ph.peers = map[string]*peer{}
		})

		It("fails with request from wrong peer", func() {
			msg := &addshare.Message{
				Type: addshare.Type_NewBk,
				Id:   "invalid-peer",
				Body: &addshare.Message_NewBk{
					NewBk: &addshare.BodyNewBk{
						Bk: newBk.ToMessage(),
					},
				},
			}
			err := ph.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(tss.ErrInvalidMsg))
		})

		It("invalid x", func() {
			invalidBk := birkhoffinterpolation.NewBkParameter(big.NewInt(0), uint32(0))
			msg := &addshare.Message{
				Type: addshare.Type_NewBk,
				Id:   peerID,
				Body: &addshare.Message_NewBk{
					NewBk: &addshare.BodyNewBk{
						Bk: invalidBk.ToMessage(),
					},
				},
			}
			err := ph.HandleMessage(log.Discard(), msg)
			Expect(err).Should(Equal(utils.ErrNotInRange))
		})

		It("fails to get add share coefficient", func() {
			// Threshold to be 0 will make it fail in function GetAddShareCoefficient.
			ph.threshold = uint32(0)
			ph.peerNum = 0
			ph.newPeer = newPeer("new-peer")
			ph.newPeer.peer = &peerData{
				bk: newBk,
			}
			h, err := ph.Finalize(log.Discard())
			Expect(err).ShouldNot(BeNil())
			Expect(h).Should(BeNil())
		})
	})
})
