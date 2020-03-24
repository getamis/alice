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
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/crypto/tss/message/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("pubkey handler, negative cases", func() {
	var (
		ph *pubkeyHandler

		peerId = "peer-id"
	)

	BeforeEach(func() {
		ph = &pubkeyHandler{
			peers: map[string]*peer{},
		}
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			ph.peers[peerId] = &peer{}
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeTrue())
		})

		It("message is not handled before", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})
	})

	Context("HandleMessage/Finalize", func() {
		var (
			signers   map[string]*Signer
			listeners map[string]*mocks.StateChangedListener
		)
		BeforeEach(func() {
			signers, listeners = newTestSigners()
		})

		AfterEach(func() {
			for _, l := range listeners {
				l.On("OnStateChanged", types.StateInit, types.StateFailed).Return().Once()
			}
			for _, s := range signers {
				s.Stop()
			}
			time.Sleep(500 * time.Millisecond)
			for _, l := range listeners {
				l.AssertExpectations(GinkgoT())
			}
		})

		It("invalid pubkey message", func() {
			bigPrime, _ := new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)
			safeParameter := 1348
			for _, s := range signers {
				cl, err := cl.NewCL(big.NewInt(1024), 40, bigPrime, safeParameter, 80)
				Expect(err).Should(BeNil())
				invalidMsg := s.GetPubkeyMessage()
				invalidMsg.Body = &Message_Pubkey{
					Pubkey: &BodyPublicKey{
						Pubkey:       cl.ToPubKeyBytes(),
						AgCommitment: invalidMsg.GetPubkey().GetAgCommitment(),
					},
				}
				Expect(s.ph.HandleMessage(log.Discard(), invalidMsg)).ShouldNot(BeNil())
			}
		})
	})
})

func newTestSigners() (map[string]*Signer, map[string]*mocks.StateChangedListener) {
	curve := btcec.S256()
	ss := [][]*big.Int{
		{big.NewInt(1094), big.NewInt(591493497), big.NewInt(0)},
		{big.NewInt(59887), big.NewInt(58337825), big.NewInt(1)},
		{big.NewInt(6542), big.NewInt(20894113809), big.NewInt(0)},
	}
	gScale := big.NewInt(5987)
	expPublic := ecpointgrouplaw.ScalarBaseMult(curve, gScale)
	return newSigners(curve, expPublic, ss, []byte{1, 2, 3})
}
