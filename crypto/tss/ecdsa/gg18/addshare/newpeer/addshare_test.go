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
	"testing"
	"time"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/gg18/addshare"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAddShare(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Add Share Suite")
}

var _ = Describe("AddShare", func() {
	It("NewAddShare", func() {
		curve := elliptic.Secp256k1()
		fieldOrder := curve.Params().N
		threshold := uint32(1)

		// new peer static information
		newPeerRank := uint32(0)
		listener := new(mocks.StateChangedListener)
		listener.On("OnStateChanged", types.StateInit, types.StateDone).Once()

		// old peer static information
		oldPeerID := tss.GetTestID(1)
		oldPeerRank := uint32(0)
		oldPeerX := big.NewInt(5)
		oldPeerBk := birkhoffinterpolation.NewBkParameter(oldPeerX, oldPeerRank)

		// Build public key, polynomial, and old peer share.
		poly, err := polynomial.RandomPolynomial(fieldOrder, threshold-1)
		Expect(err).Should(BeNil())
		pubkey := ecpointgrouplaw.ScalarBaseMult(curve, poly.Get(0))
		pubkeyMsg, err := pubkey.ToEcPointMessage()
		Expect(err).Should(BeNil())
		newPoly := poly.Differentiate(oldPeerRank)
		oldPeerShare := newPoly.Evaluate(oldPeerX)
		siGProofMsg, err := zkproof.NewBaseSchorrMessage(curve, oldPeerShare)
		Expect(err).Should(BeNil())
		pm := tss.NewTestPeerManager(0, 2)

		// Create and start a new addShare process.
		addShare := NewAddShare(pm, pubkey, threshold, newPeerRank, listener)
		r, err := addShare.GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
		addShare.Start()

		// Send the old peer information to the new peer.
		oldPeerMsg := &addshare.Message{
			Type: addshare.Type_OldPeer,
			Id:   oldPeerID,
			Body: &addshare.Message_OldPeer{
				OldPeer: &addshare.BodyOldPeer{
					Bk:          oldPeerBk.ToMessage(),
					SiGProofMsg: siGProofMsg,
					Pubkey:      pubkeyMsg,
					Threshold:   threshold,
				},
			},
		}
		Expect(addShare.AddMessage(oldPeerMsg)).Should(BeNil())
		time.Sleep(1 * time.Second)

		// Expect that the peer handler handled the message but the result handler hasn't handled the message yet.
		Expect(addShare.ph.IsHandled(log.Discard(), oldPeerID)).Should(BeTrue())
		h := addShare.GetHandler()
		rh, ok := h.(*resultHandler)
		Expect(ok).Should(BeTrue())
		Expect(rh.IsHandled(log.Discard(), oldPeerID)).Should(BeFalse())

		// Build delta.
		newPeerBk := rh.bk
		bks := birkhoffinterpolation.BkParameters{oldPeerBk}
		co, err := bks.GetAddShareCoefficient(oldPeerBk, newPeerBk, fieldOrder, threshold)
		Expect(err).Should(BeNil())
		delta := new(big.Int).Mul(co, oldPeerShare)
		delta.Mod(delta, fieldOrder)

		// Send delta to the new peer.
		resultMsg := &addshare.Message{
			Type: addshare.Type_Result,
			Id:   oldPeerID,
			Body: &addshare.Message_Result{
				Result: &addshare.BodyResult{
					Delta: delta.Bytes(),
				},
			},
		}
		Expect(addShare.AddMessage(resultMsg)).Should(BeNil())
		time.Sleep(1 * time.Second)

		// Expect that the result handler handled the message and the result is correct.
		addShare.Stop()
		h = addShare.GetHandler()
		rh, ok = h.(*resultHandler)
		Expect(ok).Should(BeTrue())
		Expect(rh.IsHandled(log.Discard(), oldPeerID)).Should(BeTrue())
		r, err = addShare.GetResult()
		Expect(err).Should(BeNil())
		Expect(r.Share).ShouldNot(BeNil())
		Expect(r.PublicKey).Should(Equal(pubkey))
	})
})
