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
package liss

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/alice/internal/message/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("liss test", func() {
	It("should be ok", func() {
		threshold := 2
		totalParticipant := 3

		lisses, listeners := newLiss([]*GroupConfig{
			{
				Users:     totalParticipant,
				Threshold: threshold,
			},
			{
				Users:     totalParticipant,
				Threshold: threshold,
			},
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

		for _, s := range lisses {
			s.Start()
		}
		for _, ch := range doneChs {
			<-ch
		}

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		// Verification
		// partialShare1 := make([]map[string]*big.Int, len(partialShareMsg1))
		// commitmentM1 := make([]map[string]*bqForm.BQuadraticForm, len(partialShareMsg1))
		// for i := 0; i < len(partialShare1); i++ {
		// 	partialShare1[i] = partialShareMsg1[i].PartailInfo.ToMap()
		// 	commitmentM1[i], err = partialShareMsg1[i].ShareCommitMsg.ToMap()
		// 	Expect(err).Should(BeNil())
		// }
		// partialShare2 := make([]map[string]*big.Int, len(partialShareMsg2))
		// commitmentM2 := make([]map[string]*bqForm.BQuadraticForm, len(partialShareMsg2))
		// for i := 0; i < len(partialShare2); i++ {
		// 	partialShare2[i] = partialShareMsg2[i].PartailInfo.ToMap()
		// 	commitmentM2[i], err = partialShareMsg2[i].ShareCommitMsg.ToMap()
		// 	Expect(err).Should(BeNil())
		// }
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
					s := new(big.Int).Add(v.Share, other.Share)
					got, err := clParameter.GetG().Exp(s)
					Expect(err).Should(BeNil())
					Expect(got).Should(Equal(v.Bq))
				}
			}
		}
	})
})

func TestLiss(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Liss Test")
}

func newLiss(configs GroupConfigs) (map[string]*Liss, map[string]*mocks.StateChangedListener) {
	lens := len(configs)
	lisses := make(map[string]*Liss, lens)
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
		lisses[id], err = NewLiss(peerManagers[i], configs, listeners[id])
		Expect(err).Should(BeNil())

		lissesMain[id] = lisses[id]
	}
	return lisses, listeners
}
