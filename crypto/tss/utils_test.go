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
package tss

import (
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/commitment"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestTSSUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TSS Utils Suite")
}

var _ = Describe("Utils", func() {
	Context("NewCommitterByPoint/GetPointFromHashCommitment", func() {
		It("should be ok", func() {
			p := pt.NewIdentity(btcec.S256())
			c, err := NewCommitterByPoint(p, 100)
			Expect(err).Should(BeNil())
			Expect(c).ShouldNot(BeNil())

			got, err := GetPointFromHashCommitment(log.Discard(), c.GetCommitmentMessage(), c.GetDecommitmentMessage())
			Expect(err).Should(BeNil())
			Expect(got.Equal(p)).Should(BeTrue())
		})

		It("failed to new by empty point", func() {
			c, err := NewCommitterByPoint(&pt.ECPoint{}, 100)
			Expect(err).ShouldNot(BeNil())
			Expect(c).Should(BeNil())
		})

		It("not an ec point", func() {
			cm, err := commitment.NewHashCommitmenter([]byte{1, 2, 3}, 100)
			Expect(err).Should(BeNil())
			got, err := GetPointFromHashCommitment(log.Discard(), cm.GetCommitmentMessage(), cm.GetDecommitmentMessage())
			Expect(err).ShouldNot(BeNil())
			Expect(got).Should(BeNil())
		})
	})

})
