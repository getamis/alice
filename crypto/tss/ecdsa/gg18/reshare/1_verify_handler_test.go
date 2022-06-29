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
	"time"

	"github.com/getamis/alice/crypto/commitment"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("verify handler, negative cases", func() {
	var (
		peerId = "peer-id"

		reshares  map[string]*Reshare
		listeners map[string]*mocks.StateChangedListener
	)
	BeforeEach(func() {
		reshares, listeners = newTestReshares()
		// Override peer manager
		for _, r := range reshares {
			p := newStopPeerManager(Type_Verify, r.ch.peerManager)
			r.ch.peerManager = p
		}

		for _, r := range reshares {
			r.Start()
		}
		// Wait reshares to handle decommit messages
		for _, s := range reshares {
			for {
				_, ok := s.GetHandler().(*verifyHandler)
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
				rh, ok := r.GetHandler().(*verifyHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})

		It("message is handled before", func() {
			for _, r := range reshares {
				rh, ok := r.GetHandler().(*verifyHandler)
				rh.peers[peerId] = &peer{
					verify: &verifyData{},
				}
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeTrue())
			}
		})

		It("message is not handled before", func() {
			for _, r := range reshares {
				rh, ok := r.GetHandler().(*verifyHandler)
				Expect(ok).Should(BeTrue())
				Expect(rh.IsHandled(log.Discard(), peerId)).Should(BeFalse())
			}
		})
	})

	Context("HandleMessage/Finalize", func() {
		var fromId, toId string
		var fromH, toH *verifyHandler
		BeforeEach(func() {
			var ok bool
			fromId = tss.GetTestID(1)
			fromR := reshares[fromId]
			fromH, ok = fromR.GetHandler().(*verifyHandler)
			Expect(ok).Should(BeTrue())

			toId = tss.GetTestID(0)
			toR := reshares[toId]
			toH, ok = toR.GetHandler().(*verifyHandler)
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

		It("failed to verify message", func() {
			msg := fromH.peers[toId].peer.verifyMessage
			invalidMessage := &Message{
				Type: msg.Type,
				Id:   msg.Id,
				Body: &Message_Verify{
					Verify: &BodyVerify{
						Verify: &commitment.FeldmanVerifyMessage{},
					},
				},
			}
			err := toH.HandleMessage(log.Discard(), invalidMessage)
			Expect(err).Should(Equal(commitment.ErrFailedVerify))
		})
	})
})
