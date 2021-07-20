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
package aggregator

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/getamis/alice/crypto/liss"
	"github.com/getamis/alice/crypto/liss/share"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/libs/message/types"
	"github.com/getamis/alice/libs/message/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("liss test", func() {
	It("should be ok", func() {
		threshold := 2
		totalParticipant := 3
		configs := []*liss.GroupConfig{
			{
				Users:     totalParticipant,
				Threshold: threshold,
			},
			{
				Users:     totalParticipant,
				Threshold: threshold,
			},
		}
		lisses, listeners := newLiss(configs)
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

		for _, s := range lisses {
			s.Start()
		}
		for _, ch := range doneChs {
			<-ch
		}

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		r0, err := lisses["id-0"].GetResult()
		Expect(err).Should(BeNil())
		r1, err := lisses["id-1"].GetResult()
		Expect(err).Should(BeNil())
		Expect(r0.PublicKey).Should(Equal(r1.PublicKey))
		for group, users := range r0.Users {
			for i, m := range users {
				for k, v := range m {
					other := r1.Users[group][i][k]
					Expect(v.Bq).Should(Equal(other.Bq))
				}
			}
		}

		userResults := make([][]*share.UserResult, len(configs))
		for i, c := range configs {
			userResults[i] = make([]*share.UserResult, c.Users)
			for j := 0; j < c.Users; j++ {
				u0 := r0.GetUserResult(i, j)
				u1 := r1.GetUserResult(i, j)
				userResults[i][j], err = share.ComineShares(c, j, []*share.UserResult{
					u0,
					u1,
				})
				Expect(err).Should(BeNil())
			}
		}

		// Generate signature And proof
		S256 := btcec.S256()
		privKey := big.NewInt(101)
		tssPubKey := pt.ScalarBaseMult(S256, privKey)
		k := big.NewInt(1100019879798798)
		message := big.NewInt(11231)
		R := pt.ScalarBaseMult(S256, k)
		Rx := R.GetX()
		s1 := big.NewInt(298374927)
		s2, _ := new(big.Int).SetString("19648591900156574905646002538671153035796200247616928483347707833477501056209", 10)
		s := new(big.Int).Add(s1, s2)

		pubKey := r0.PublicKey
		cosistencyProof1, err := pubKey.BuildConsistencyProof(s1.Bytes(), R)
		Expect(err).Should(BeNil())
		cosistencyProof2, err := pubKey.BuildConsistencyProof(s2.Bytes(), R)
		Expect(err).Should(BeNil())

		proofs := []*cl.ConsistencyProofMessage{
			cosistencyProof1,
			cosistencyProof2,
		}

		// Aggregate shares
		agg, err := NewAggregator(configs, tssPubKey, pubKey, Rx, message, proofs)
		Expect(err).Should(BeNil())
		users := make([][]*User, len(userResults))
		for i := 0; i < len(userResults); i++ {
			users[i] = make([]*User, len(userResults[i]))
			for j := 0; j < len(userResults[i]); j++ {
				users[i][j], err = NewUser(tssPubKey, pubKey, Rx, message, proofs, userResults[i][j])
				Expect(err).Should(BeNil())
				approve, err := users[i][j].Approve()
				Expect(err).Should(BeNil())
				Expect(agg.Add(i, j, approve)).Should(BeTrue())
			}
		}
		Expect(agg.IsEnough()).Should(BeTrue())
		gotS, err := agg.GetS()
		Expect(err).Should(BeNil())
		Expect(gotS).Should(Equal(s))
	})
})

func TestAggregator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Aggregator Test")
}

func newLiss(configs liss.GroupConfigs) (map[string]*share.Liss, map[string]*mocks.StateChangedListener) {
	lens := len(configs)
	lisses := make(map[string]*share.Liss, lens)
	lissesMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)

	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(lissesMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		if i == 0 {
			lisses[id], err = share.NewServerLiss(peerManagers[i], configs, listeners[id])
		} else {
			lisses[id], err = share.NewUserLiss(peerManagers[i], configs, listeners[id])
		}
		Expect(err).Should(BeNil())

		lissesMain[id] = lisses[id]
	}
	return lisses, listeners
}
