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

package dkg

import (
	"math/big"

	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("DKG threshold secrecy", func() {
	var (
		curve = elliptic.Secp256k1()
	)

	// awaitState arms every listener for the transition StateInit -> state and blocks
	// until each fired; arm before Start so no transition goes unexpected.
	awaitState := func(listeners map[string]*mocks.StateChangedListener, state types.MainState, start func()) {
		chs := make([]chan struct{}, 0, len(listeners))
		for _, l := range listeners {
			ch := make(chan struct{})
			chs = append(chs, ch)
			l.On("OnStateChanged", types.StateInit, state).Run(func(mock.Arguments) {
				close(ch)
			}).Once()
		}
		start()
		for _, ch := range chs {
			Eventually(ch, "10s").Should(BeClosed())
		}
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	}

	It("the threshold-3 pair (2u, 0), (u, 1) fails every member before a share is dealt", func() {
		// Self-declared parameters, as the plain NewDKG path accepts them.
		coefficients := [][]*big.Int{
			{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
			{big.NewInt(4), big.NewInt(5), big.NewInt(6)},
			{big.NewInt(7), big.NewInt(8), big.NewInt(9)},
		}
		x := []*big.Int{big.NewInt(2), big.NewInt(1), big.NewInt(3)}
		ranks := []uint32{0, 1, 0}
		dkgs, listeners := newDKGWithPeerHandler(curve, 3, ranks, x, coefficients)
		awaitState(listeners, types.StateFailed, func() {
			for _, d := range dkgs {
				d.Start()
			}
		})
		// Shares travel in the verify message a member sends on receiving a decommit;
		// no member got as far as a decommit.
		for _, d := range dkgs {
			d.Stop()
			for _, peer := range d.ph.peers {
				Expect(peer.decommit).Should(BeNil())
			}
		}
	})

})
