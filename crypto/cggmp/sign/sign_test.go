// Copyright © 2022 AMIS Technologies
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
package sign

import (
	"math/big"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/alice/internal/message/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestDKG(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sign Suite")
}

var (
	threshold = uint32(2)
	secret    = big.NewInt(1)
	curve     = elliptic.Secp256k1()
	publicKey = pt.ScalarBaseMult(curve, secret)
	msg       = []byte("Edwin HaHa")
)

var _ = Describe("Refresh", func() {
	It("should be ok", func() {
		signs, _, listeners := newSigns()
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, d := range signs {
			d.Start()
		}
		time.Sleep(10 * time.Second)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		r0, err := signs[tss.GetTestID(0)].GetResult()
		Expect(err).Should(BeNil())
		r1, err := signs[tss.GetTestID(1)].GetResult()
		Expect(err).Should(BeNil())
		Expect(r0.R.Cmp(r1.R) == 0).Should(BeTrue())
		Expect(r0.S.Cmp(r1.S) == 0).Should(BeTrue())
	})
})

func newSigns() (map[string]*Sign, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	lens := 2
	signs := make(map[string]*Sign, lens)
	signsMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	bks := map[string]*birkhoffinterpolation.BkParameter{
		tss.GetTestID(0): birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0),
		tss.GetTestID(1): birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0),
	}
	shares := []*big.Int{
		big.NewInt(2),
		big.NewInt(3),
	}
	keySize := 2048
	ssidInfo := []byte("A")
	paillierKeyA, err := paillier.NewPaillierSafePrime(keySize)
	Expect(err).Should(BeNil())
	paillierKeyB, err := paillier.NewPaillierSafePrime(keySize)
	Expect(err).Should(BeNil())
	pedA, err := paillierKeyA.NewPedersenParameterByPaillier()
	Expect(err).Should(BeNil())
	pedB, err := paillierKeyB.NewPedersenParameterByPaillier()
	Expect(err).Should(BeNil())

	paillierKey := []*paillier.Paillier{
		paillierKeyA,
		paillierKeyB,
	}
	partialPubKey := make(map[string]*pt.ECPoint)
	partialPubKey[tss.GetTestID(0)] = pt.ScalarBaseMult(curve, shares[0])
	partialPubKey[tss.GetTestID(1)] = pt.ScalarBaseMult(curve, shares[1])
	allY := make(map[string]*pt.ECPoint)
	allY[tss.GetTestID(0)] = pt.ScalarBaseMult(curve, big.NewInt(100))
	allY[tss.GetTestID(1)] = pt.ScalarBaseMult(curve, big.NewInt(200))
	allPed := make(map[string]*paillier.PederssenOpenParameter)
	allPed[tss.GetTestID(0)] = pedA.PedersenOpenParameter
	allPed[tss.GetTestID(1)] = pedB.PedersenOpenParameter
	// rho := []byte("Una HaHa")

	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(signsMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		signs[id], err = NewSign(threshold, ssidInfo, shares[i], publicKey, partialPubKey, allY, paillierKey[i], allPed, bks, msg, peerManagers[i], listeners[id])
		Expect(err).Should(BeNil())
		signsMain[id] = signs[id]
		r, err := signs[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return signs, bks, listeners
}
