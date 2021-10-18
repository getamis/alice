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
package commitment

import (
	"bytes"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/blake2b"
)

func TestCommitment(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Commitment Suite")
}

var _ = Describe("hash", func() {
	Context("hash", func() {
		It("should be ok", func() {
			By("Compute hashcommitment")
			data, err := utils.GenRandomBytes(256)
			Expect(err).To(BeNil())
			sendCommitment, err := NewHashCommitmenter(data)
			Expect(err).To(BeNil())

			By("Send commitment")
			commitmentMsg := sendCommitment.GetCommitmentMessage()

			By("Ask for original data and salt for decommit")
			decommitmentMsg := sendCommitment.GetDecommitmentMessage()

			By("Decommit by receiver")
			expected := commitmentMsg.Decommit(decommitmentMsg)
			Expect(expected).To(BeNil())
		})

		It("empty input data", func() {
			data, err := utils.GenRandomBytes(0)
			Expect(err).To(Equal(utils.ErrEmptySlice))
			Expect(data).To(BeNil())
		})

		It("different data", func() {
			data, err := utils.GenRandomBytes(256)
			Expect(err).To(BeNil())
			getcommitment, err := NewHashCommitmenter(data)
			Expect(err).To(BeNil())
			decommitmentMsg := getcommitment.GetDecommitmentMessage()
			otherdata, err := utils.GenRandomBytes(2)
			Expect(err).To(BeNil())

			decommitmentMsg.Data = otherdata
			result := getcommitment.GetCommitmentMessage().Decommit(decommitmentMsg)
			Expect(result).To(Equal(ErrDifferentDigest))
		})

		It("different salt", func() {
			data, err := utils.GenRandomBytes(blake2b.Size256)
			Expect(err).To(BeNil())
			getcommitment, err := NewHashCommitmenter(data)
			Expect(err).To(BeNil())
			decommitmentMsg := getcommitment.GetDecommitmentMessage()
			otherSalt, err := utils.GenRandomBytes(blake2b.Size256)
			Expect(err).To(BeNil())

			decommitmentMsg.Salt = otherSalt
			result := getcommitment.GetCommitmentMessage().Decommit(decommitmentMsg)
			Expect(result).To(Equal(ErrDifferentDigest))
		})

		It("long blake2b key", func() {
			commitMsg := &HashCommitmentMessage{}
			Expect(commitMsg.Decommit(&HashDecommitmentMessage{
				Salt: bytes.Repeat([]byte{2}, 33),
			})).ShouldNot(BeNil())
		})
	})

	Context("NewProtoHashCommitmenter/DecommitToProto", func() {
		It("should be ok", func() {
			exp := &HashDecommitmentMessage{
				Data: []byte{1, 2, 3},
				Salt: []byte{4, 5, 6},
			}
			c, err := NewProtoHashCommitmenter(exp)
			Expect(err).Should(BeNil())
			Expect(c).ShouldNot(BeNil())

			got := &HashDecommitmentMessage{}
			err = c.GetCommitmentMessage().DecommitToProto(c.GetDecommitmentMessage(), got)
			Expect(err).Should(BeNil())
			Expect(exp.Data).Should(Equal(got.Data))
			Expect(exp.Salt).Should(Equal(got.Salt))
		})

		It("nil message", func() {
			c, err := NewProtoHashCommitmenter(nil)
			Expect(err).ShouldNot(BeNil())
			Expect(c).Should(BeNil())
		})

		It("invalid commit message", func() {
			exp := &HashDecommitmentMessage{
				Data: []byte{1, 2, 3},
				Salt: []byte{4, 5, 6},
			}
			c, err := NewProtoHashCommitmenter(exp)
			Expect(err).Should(BeNil())
			Expect(c).ShouldNot(BeNil())

			got := &HashDecommitmentMessage{}
			err = c.GetCommitmentMessage().DecommitToProto(&HashDecommitmentMessage{}, got)
			Expect(err).ShouldNot(BeNil())
			Expect(got).Should(Equal(&HashDecommitmentMessage{}))
		})

		It("invalid proto message type", func() {
			exp := &HashDecommitmentMessage{
				Data: []byte{1, 2, 3},
				Salt: []byte{4, 5, 6},
			}
			c, err := NewProtoHashCommitmenter(exp)
			Expect(err).Should(BeNil())
			Expect(c).ShouldNot(BeNil())

			got := &PointCommitmentMessage{}
			err = c.GetCommitmentMessage().DecommitToProto(c.GetDecommitmentMessage(), got)
			Expect(err).ShouldNot(BeNil())
		})
	})

	Context("NewCommitterByPoint/GetPointFromHashCommitment", func() {
		It("should be ok", func() {
			p := pt.NewIdentity(secp256k1)
			c, err := NewCommitterByPoint(p)
			Expect(err).Should(BeNil())
			Expect(c).ShouldNot(BeNil())

			got, err := GetPointFromHashCommitment(c.GetCommitmentMessage(), c.GetDecommitmentMessage())
			Expect(err).Should(BeNil())
			Expect(got.Equal(p)).Should(BeTrue())
		})

		It("failed to new by empty point", func() {
			c, err := NewCommitterByPoint(&pt.ECPoint{})
			Expect(err).ShouldNot(BeNil())
			Expect(c).Should(BeNil())
		})

		It("not an ec point", func() {
			cm, err := NewHashCommitmenter([]byte{1, 2, 3})
			Expect(err).Should(BeNil())
			got, err := GetPointFromHashCommitment(cm.GetCommitmentMessage(), cm.GetDecommitmentMessage())
			Expect(err).ShouldNot(BeNil())
			Expect(got).Should(BeNil())
		})
	})

})
