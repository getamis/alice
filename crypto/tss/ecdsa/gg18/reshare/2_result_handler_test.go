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
package reshare

import (
	"math/big"
	"time"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/matrix"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("result handler, negative cases", func() {
	var (
		peerId = "peer-id"

		reshares  map[string]*Reshare
		listeners map[string]*mocks.StateChangedListener
	)
	BeforeEach(func() {
		reshares, listeners = newTestReshares()
		// Override peer manager
		for _, r := range reshares {
			p := newStopPeerManager(Type_Result, r.ch.peerManager)
			r.ch.peerManager = p
		}

		for _, r := range reshares {
			r.Start()
		}
		// Wait reshares to handle decommit messages
		for _, s := range reshares {
			for {
				_, ok := s.GetHandler().(*resultHandler)
				if !ok {
					time.Sleep(500 * time.Millisecond)
					continue
				}
				break
			}
		}
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateFailed).Return().Once()
		}
	})

	AfterEach(func() {
		for _, r := range reshares {
			r.Stop()
		}
		time.Sleep(500 * time.Millisecond)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	})

	Context("IsHandled", func() {
		It("peer not found", func() {
			for _, r := range reshares {
				rh, ok := r.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})

		It("message is handled before", func() {
			for _, r := range reshares {
				rh, ok := r.GetHandler().(*resultHandler)
				rh.peers[peerId] = &peer{
					result: &resultData{},
				}
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
			}
		})

		It("message is not handled before", func() {
			for _, r := range reshares {
				rh, ok := r.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})
	})

	Context("HandleMessage/Finalize", func() {
		var fromId, toId string
		var fromH, toH *resultHandler
		BeforeEach(func() {
			var ok bool
			fromId = tss.GetTestID(1)
			fromR := reshares[fromId]
			fromH, ok = fromR.GetHandler().(*resultHandler)
			Expect(ok).Should(BeTrue())

			toId = tss.GetTestID(0)
			toR := reshares[toId]
			toH, ok = toR.GetHandler().(*resultHandler)
			Expect(ok).Should(BeTrue())
		})

		It("peer not found", func() {
			msg := &Message{
				Id: "invalid peer",
			}
			for _, r := range reshares {
				Expect(r.GetHandler().HandleMessage(log.Discard(), msg)).Should(Equal(tss.ErrPeerNotFound))
			}
		})

		It("invalid V point message", func() {
			msg := fromH.getResultMessage()
			invalidMessage := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_Result{
					Result: &BodyResult{
						SiGProofMsg: &zkproof.SchnorrProofMessage{
							V: &ecpointgrouplaw.EcPointMessage{
								Curve: ecpointgrouplaw.EcPointMessage_EDWARD25519,
							},
							Alpha: msg.GetResult().GetSiGProofMsg().GetAlpha(),
						},
					},
				},
			}
			err := toH.HandleMessage(log.New(), invalidMessage)
			Expect(err).Should(Equal(zkproof.ErrDifferentCurves))
		})
	})

	Context("Finalize", func() {
		var toH *resultHandler
		BeforeEach(func() {
			var ok bool
			toId := tss.GetTestID(0)
			toR := reshares[toId]
			toH, ok = toR.GetHandler().(*resultHandler)
			Expect(ok).Should(BeTrue())

			for fromId, r := range reshares {
				if toId == fromId {
					continue
				}
				fromR, ok := r.GetHandler().(*resultHandler)
				Expect(ok).Should(BeTrue())
				Expect(toH.HandleMessage(log.Discard(), fromR.getResultMessage())).Should(BeNil())
			}
		})

		It("invalid self V point", func() {
			toH.siGProofMsg.V = &ecpointgrouplaw.EcPointMessage{
				Curve: ecpointgrouplaw.EcPointMessage_Curve(99),
			}
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ecpointgrouplaw.ErrInvalidCurve))
		})

		It("failed to compute bks", func() {
			// duplicate bk
			toH.bk = birkhoffinterpolation.NewBkParameter(big.NewInt(4), uint32(0))
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(matrix.ErrNotInvertableMatrix))
		})

		It("failed to compute linear combinations", func() {
			var err error
			toH.siGProofMsg.V, err = ecpointgrouplaw.NewBase(elliptic.Ed25519()).ToEcPointMessage()
			Expect(err).Should(BeNil())
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ecpointgrouplaw.ErrDifferentCurve))
		})

		It("inconsistent public key", func() {
			var err error
			toH.siGProofMsg.V, err = ecpointgrouplaw.NewBase(elliptic.Secp256k1()).ToEcPointMessage()
			Expect(err).Should(BeNil())
			got, err := toH.Finalize(log.Discard())
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(tss.ErrInconsistentPubKey))
		})
	})
})
