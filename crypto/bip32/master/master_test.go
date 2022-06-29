// Copyright © 2021 AMIS Technologies
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

package master

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

const (
	circuitPtah = "../../circuit/bristolFashion/MPCSEED.txt"
)

var _ = Describe("Bip32 test", func() {
	sid := []byte("adsfsdfs")
	DescribeTable("With seed", func(seedstring, expected string, p string) {
		seed, _ := hex.DecodeString(seedstring)
		aliceSeed := seed[0:32]
		bobSeed := seed[32:64]

		masters, listeners := newMastersWithSeed(sid, [][]byte{
			aliceSeed,
			bobSeed,
		})

		doneChs := make([]chan struct{}, 2)
		i := 0
		for _, l := range listeners {
			doneChs[i] = make(chan struct{})
			doneCh := doneChs[i]
			l.On("OnStateChanged", types.StateInit, types.StateDone).Run(func(args mock.Arguments) {
				close(doneCh)
			}).Once()
			i++
		}

		for _, s := range masters {
			s.Start()
		}
		for _, ch := range doneChs {
			<-ch
		}

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		// Validate output
		privateKey := new(big.Int)
		for _, s := range masters {
			r, err := s.GetResult()
			Expect(err).Should(BeNil())
			Expect(hex.EncodeToString(r.ChainCode)).Should(Equal(expected[64:]))
			h := s.GetHandler()
			rh, ok := h.(*verifyHandler)
			Expect(ok).Should(BeTrue())
			privateKey = new(big.Int).Add(privateKey, rh.randomChoose)
			privateKey = new(big.Int).Sub(privateKey, s.ih.randomSeed)
		}
		big2 := big.NewInt(2)
		pBig, _ := new(big.Int).SetString(p, 10)
		privateKey.Mul(privateKey, new(big.Int).ModInverse(big2, pBig))
		privateKey.Mod(privateKey, pBig)
		expectedPrivateKey, _ := new(big.Int).SetString(expected[0:64], 16)
		Expect(expectedPrivateKey).Should(Equal(privateKey))
	},
		Entry("case1:", "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689", "115792089237316195423570985008687907852837564279074904382605163141518161494337"),
	)

	It("Without seed", func() {
		masters, listeners := newMasters(sid)
		doneChs := make([]chan struct{}, 2)
		i := 0
		for _, l := range listeners {
			doneChs[i] = make(chan struct{})
			doneCh := doneChs[i]
			l.On("OnStateChanged", types.StateInit, types.StateDone).Run(func(args mock.Arguments) {
				close(doneCh)
			}).Once()
			i++
		}

		for _, s := range masters {
			s.Start()
		}
		for _, ch := range doneChs {
			<-ch
		}

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	})
})

func TestBip32(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Master Test")
}

func newMastersWithSeed(sid []uint8, ss [][]byte) (map[string]*Master, map[string]*mocks.StateChangedListener) {
	threshold := len(ss)
	masters := make(map[string]*Master, threshold)
	mastersMain := make(map[string]types.MessageMain, threshold)
	peerManagers := make([]types.PeerManager, threshold)
	listeners := make(map[string]*mocks.StateChangedListener, threshold)

	for i := 0; i < len(ss); i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, threshold)
		pm.Set(mastersMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		if i == 0 {
			masters[id], err = newAlice(peerManagers[i], sid, ss[i], 0, circuitPtah, listeners[id])
			Expect(err).Should(BeNil())
		} else if i == 1 {
			masters[id], err = newBob(peerManagers[i], sid, ss[i], 0, circuitPtah, listeners[id])
			Expect(err).Should(BeNil())
		}

		mastersMain[id] = masters[id]
	}
	return masters, listeners
}

func newMasters(sid []uint8) (map[string]*Master, map[string]*mocks.StateChangedListener) {
	masters := make(map[string]*Master, Threshold)
	mastersMain := make(map[string]types.MessageMain, Threshold)
	peerManagers := make([]types.PeerManager, Threshold)
	listeners := make(map[string]*mocks.StateChangedListener, Threshold)

	for i := 0; i < Threshold; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, Threshold)
		pm.Set(mastersMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		if i == 0 {
			masters[id], err = NewAlice(peerManagers[i], sid, 0, circuitPtah, listeners[id])
			Expect(err).Should(BeNil())
		} else if i == 1 {
			masters[id], err = NewBob(peerManagers[i], sid, 0, circuitPtah, listeners[id])
			Expect(err).Should(BeNil())
		}

		mastersMain[id] = masters[id]
	}
	return masters, listeners
}
