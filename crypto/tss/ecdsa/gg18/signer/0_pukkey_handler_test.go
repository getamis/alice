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
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/cl"
	homoMocks "github.com/getamis/alice/crypto/homo/mocks"
	"github.com/getamis/alice/crypto/matrix"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
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

	Context("newPubkeyHandler", func() {
		var (
			mockPeerManager *mocks.PeerManager
			mockHomo        *homoMocks.Crypto

			curve = elliptic.Secp256k1()
			bks   = map[string]*birkhoffinterpolation.BkParameter{
				"1": birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0),
				"2": birkhoffinterpolation.NewBkParameter(big.NewInt(10), 0),
				"3": birkhoffinterpolation.NewBkParameter(big.NewInt(20), 0),
			}
			gScale     = big.NewInt(5987)
			expPublic  = ecpointgrouplaw.ScalarBaseMult(curve, gScale)
			unknownErr = errors.New("unknown error")
		)
		BeforeEach(func() {
			mockPeerManager = new(mocks.PeerManager)
			mockHomo = new(homoMocks.Crypto)
		})
		AfterEach(func() {
			mockPeerManager.AssertExpectations(GinkgoT())
			mockHomo.AssertExpectations(GinkgoT())
		})

		It("inconsistent peer number and bks", func() {
			mockPeerManager.On("NumPeers").Return(uint32(3)).Once()
			got, err := newPubkeyHandler(expPublic, mockPeerManager, mockHomo, nil, bks, nil)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrInconsistentPeerNumAndBks))
		})

		It("failed to do homo encryption", func() {
			mockPeerManager.On("NumPeers").Return(uint32(2)).Once()
			mockHomo.On("Encrypt", mock.Anything).Return(nil, unknownErr).Once()
			got, err := newPubkeyHandler(expPublic, mockPeerManager, mockHomo, nil, bks, nil)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(unknownErr))
		})

		It("self id not found", func() {
			mockPeerManager.On("NumPeers").Return(uint32(2)).Once()
			mockHomo.On("Encrypt", mock.Anything).Return([]byte("enc k"), nil).Once()
			mockPeerManager.On("SelfID").Return("not found").Once()
			got, err := newPubkeyHandler(expPublic, mockPeerManager, mockHomo, nil, bks, nil)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrSelfBKNotFound))
		})

		It("duplicate bks", func() {
			dupBks := map[string]*birkhoffinterpolation.BkParameter{
				"1": birkhoffinterpolation.NewBkParameter(big.NewInt(10), 0),
				"2": birkhoffinterpolation.NewBkParameter(big.NewInt(10), 0),
				"3": birkhoffinterpolation.NewBkParameter(big.NewInt(20), 0),
			}
			mockPeerManager.On("NumPeers").Return(uint32(2)).Once()
			mockHomo.On("Encrypt", mock.Anything).Return([]byte("enc k"), nil).Once()
			mockPeerManager.On("SelfID").Return("1").Once()
			got, err := newPubkeyHandler(expPublic, mockPeerManager, mockHomo, nil, dupBks, nil)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(matrix.ErrNotInvertableMatrix))
		})
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			Expect(ph.IsHandled(log.Discard(), peerId)).Should(BeFalse())
		})

		It("message is handled before", func() {
			ph.peers[peerId] = &peer{
				pubkey: &pubkeyData{},
			}
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
				l.AssertExpectations(GinkgoT())
			}
		})

		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, s := range signers {
				Expect(s.ph.HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})

		It("invalid pubkey message", func() {
			bigPrime, _ := new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)
			safeParameter := 1348
			for _, s := range signers {
				cl, err := cl.NewCL(big.NewInt(1024), 40, bigPrime, safeParameter, 80)
				Expect(err).Should(BeNil())
				invalidMsg := s.ph.getPubkeyMessage()
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
	curve := elliptic.Secp256k1()
	ss := [][]*big.Int{
		{big.NewInt(1094), big.NewInt(591493497), big.NewInt(0)},
		{big.NewInt(59887), big.NewInt(58337825), big.NewInt(1)},
		{big.NewInt(6542), big.NewInt(20894113809), big.NewInt(0)},
	}
	gScale := big.NewInt(5987)
	expPublic := ecpointgrouplaw.ScalarBaseMult(curve, gScale)
	return newSigners(curve, expPublic, ss, []byte{1, 2, 3})
}
