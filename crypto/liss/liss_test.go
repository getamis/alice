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

	// DescribeTable("Group: getDecryptVector()", func(threshold int, totalParticipant int, expected []*big.Int) {
	// 	users := make([]*User, totalParticipant)
	// 	var err error
	// 	for i := 0; i < totalParticipant; i++ {
	// 		users[i], err = NewUser(threshold, totalParticipant, totalParticipant-i, nil)
	// 		Expect(err).Should(BeNil())
	// 	}
	// 	Group, err := NewGroup(users, totalParticipant, threshold)
	// 	Expect(err).Should(BeNil())
	// 	got := Group.getDecryptVector()
	// 	for i := 0; i < len(got); i++ {
	// 		Expect(got[i].Cmp(expected[i]) == 0).Should(BeTrue())
	// 	}
	// },
	// 	Entry("normal case", 2, 3, []*big.Int{
	// 		big.NewInt(1), big.NewInt(-1),
	// 	}),
	// )

	// DescribeTable("org: getDecryptVector()", func(threshold int, totalParticipant int, expected []*big.Int) {
	// 	users1 := make([]*User, totalParticipant)
	// 	users2 := make([]*User, totalParticipant)
	// 	var err error
	// 	for i := 0; i < totalParticipant; i++ {
	// 		users1[i], err = NewUser(threshold, totalParticipant, 2*totalParticipant-i-1, nil)
	// 		Expect(err).Should(BeNil())
	// 		users2[i], err = NewUser(threshold, totalParticipant, totalParticipant-i-1, nil)
	// 		Expect(err).Should(BeNil())
	// 	}
	// 	groups := make([]*Group, 2)
	// 	groups[0], err = NewGroup(users1, totalParticipant, threshold)
	// 	Expect(err).Should(BeNil())
	// 	groups[1], err = NewGroup(users2, totalParticipant, threshold)
	// 	Expect(err).Should(BeNil())
	// 	org, err := newOrginization(groups)
	// 	Expect(err).Should(BeNil())
	// 	got := org.GetDecryptVector()
	// 	for i := 0; i < len(got); i++ {
	// 		Expect(got[i].Cmp(expected[i]) == 0).Should(BeTrue())
	// 	}
	// },
	// 	Entry("normal case", 2, 3, []*big.Int{
	// 		big.NewInt(1), big.NewInt(-1), big.NewInt(-1), big.NewInt(1),
	// 	}),
	// 	Entry("normal case", 3, 4, []*big.Int{
	// 		big.NewInt(1), big.NewInt(-1), big.NewInt(-1), big.NewInt(-1), big.NewInt(1), big.NewInt(1),
	// 	}),
	// )
	// 	Context("GetDecryptCiphertext, setUserPartialDecryptCiphertext, and GetNonExistApproval", func() {
	// 		FIt("It is OK", func() {
	// 			threshold := 2
	// 			totalParticipant := 3

	// 			org, err := NewOrginization(2, []int{totalParticipant, totalParticipant}, []int{threshold, threshold})
	// 			Expect(err).Should(BeNil())
	// 			g := clKey.PublicKey.GetG()

	// 			usersPartialDecrypt := make([]map[string]*bqForm.BQuadraticForm, 6)
	// 			for i := 0; i < len(usersPartialDecrypt); i++ {
	// 				usersPartialDecrypt[i] = make(map[string]*bqForm.BQuadraticForm)
	// 			}
	// 			// set partial ciphertext
	// 			combin := combin.Combinations(totalParticipant, threshold)
	// 			for j := 0; j < len(combin); j++ {
	// 				markIndex := IntSliceToString(combin[j])
	// 				for k := 0; k < len(combin[j]); k++ {
	// 					usersPartialDecrypt[combin[j][k]][markIndex], err = g.Exp(big1)
	// 					Expect(err).Should(BeNil())
	// 				}
	// 			}
	// 			for j := 0; j < len(combin); j++ {
	// 				translateIndex := make([]int, len(combin[j]))
	// 				for k := 0; k < len(translateIndex); k++ {
	// 					translateIndex[k] = combin[j][k] + org.groups[0].numberUser
	// 				}
	// 				markIndex := IntSliceToString(translateIndex)
	// 				for k := 0; k < len(combin[j]); k++ {
	// 					usersPartialDecrypt[combin[j][k]+org.groups[0].numberUser][markIndex], err = g.Exp(big1)
	// 					Expect(err).Should(BeNil())
	// 				}
	// 			}

	// 			for i := 0; i < org.totalPeople; i++ {
	// 				if i == 1 || i == 3 {
	// 					continue
	// 				}
	// 				err := org.SetUserPartialDecryptCiphertext(i, usersPartialDecrypt[i])
	// 				Expect(err).Should(BeNil())
	// 			}
	// 			result := org.GetDecryptCiphertext()
	// 			for i := 0; i < len(result); i++ {
	// 				if i == 1 || i == 3 {
	// 					Expect(result[i]).Should(BeNil())
	// 					continue
	// 				}
	// 				Expect(result[i]).ShouldNot(BeNil())
	// 			}

	// 			// check GetNonExistApproval()
	// 			nonapprovallist := org.GetNonExistApproval()
	// 			expected := []int{1, 3}
	// 			for i := 0; i < len(nonapprovallist); i++ {
	// 				Expect(nonapprovallist[i] == expected[i]).Should(BeTrue())
	// 			}
	// 		})
	// 	})

	// })
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
