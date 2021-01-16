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
package oprf

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("oprf test", func() {
	DescribeTable("Hash()", func(pw []byte, k *big.Int) {
		copyPw := make([]byte, len(pw))
		copy(copyPw, pw)
		requester, err := NewRequester(pw)
		Expect(err).Should(BeNil())
		// Ensure the password is correct
		Expect(requester.pw).Should(Equal(copyPw))
		var responser *Responser
		if k == nil {
			responser, err = NewResponser()
			Expect(err).Should(BeNil())
			k = responser.GetK()
		} else {
			responser, err = NewResponserWithK(k)
			Expect(err).Should(BeNil())
		}
		responserMessage, err := responser.Handle(requester.GetRequestMessage())
		Expect(err).Should(BeNil())
		got, err := requester.Compute(responserMessage)
		Expect(err).Should(BeNil())

		expected, err := ComputeShare(k, pw, secp256k1Hasher)
		Expect(err).Should(BeNil())
		Expect(got.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("random k", []byte("cy hahahahahaha"), nil),
		Entry("asdfsasddfgdfs", []byte("asdfsasddfgdfs"), big.NewInt(32000000)),
		Entry("092834729837492374", []byte("092834729837492374"), big.NewInt(10000)),
		Entry("092834729-37492374", []byte("092834729-37492374"), big.NewInt(999999)),
	)

	// Warn: CAN NOT CHANGE THESE TESTS
	DescribeTable("Fix Vector()", func(pw []byte, k *big.Int, expectedString string) {
		got, err := ComputeShare(k, pw, secp256k1Hasher)
		Expect(err).Should(BeNil())
		expected, _ := new(big.Int).SetString(expectedString, 10)
		Expect(err).Should(BeNil())
		Expect(got.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("random k", []byte("cy hahahahahaha"), big.NewInt(2), "39762705969790288698147785435158915025771216702954110676076686122230821070412"),
		Entry("random k", []byte("cy hahahahahaha"), big.NewInt(3), "66160902141901830464806996240648401353488586023602583499574451231396974735128"),
		Entry("asdfsasddfgdfs", []byte("asdfsasddfgdfs"), big.NewInt(32000000), "75842743101060490522393730082400262068787578753446434023016710045513511388077"),
		Entry("092834729837492374", []byte("092834729837492374"), big.NewInt(10000), "29704828473288093072032800362891643369290824425550073036816806344369222682398"),
		Entry("092834729-37492374", []byte("092834729-37492374"), big.NewInt(999999), "80863401229445569258591851410919083324501633198301704812368958895625043366063"),
	)

	// Warn: CAN NOT CHANGE THESE TESTS
	DescribeTable("Fix Vector()", func(pw []byte, k *big.Int, expectedString string) {
		requester, err := NewRequester(pw)
		Expect(err).Should(BeNil())
		var responser *Responser
		if k == nil {
			responser, err = NewResponser()
			Expect(err).Should(BeNil())
			k = responser.GetK()
		} else {
			responser, err = NewResponserWithK(k)
			Expect(err).Should(BeNil())
		}
		responserMessage, err := responser.Handle(requester.GetRequestMessage())
		Expect(err).Should(BeNil())
		got, err := requester.Compute(responserMessage)
		Expect(err).Should(BeNil())
		expected, _ := new(big.Int).SetString(expectedString, 10)
		Expect(err).Should(BeNil())
		Expect(got.Cmp(expected) == 0).Should(BeTrue())
	},
		Entry("random k", []byte("cy hahahahahaha"), big.NewInt(2), "39762705969790288698147785435158915025771216702954110676076686122230821070412"),
		Entry("random k", []byte("cy hahahahahaha"), big.NewInt(3), "66160902141901830464806996240648401353488586023602583499574451231396974735128"),
		Entry("asdfsasddfgdfs", []byte("asdfsasddfgdfs"), big.NewInt(32000000), "75842743101060490522393730082400262068787578753446434023016710045513511388077"),
		Entry("092834729837492374", []byte("092834729837492374"), big.NewInt(10000), "29704828473288093072032800362891643369290824425550073036816806344369222682398"),
		Entry("092834729-37492374", []byte("092834729-37492374"), big.NewInt(999999), "80863401229445569258591851410919083324501633198301704812368958895625043366063"),
	)

	Context("Negative case", func() {
		It("ErrNotInRange", func() {
			responser, err := NewResponserWithK(big.NewInt(0))
			Expect(responser).Should(BeNil())
			Expect(err).Should(Equal(utils.ErrNotInRange))
		})

		It("beta : ErrInvalidPoint", func() {
			request, err := NewRequester([]byte("123"))
			Expect(err).Should(BeNil())
			got, err := request.Compute(&OprfResponseMessage{})
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(pt.ErrInvalidPoint))
		})

		It("beta : ErrIdentityPoint", func() {
			request, err := NewRequester([]byte("123"))
			Expect(err).Should(BeNil())
			responser, err := NewResponserWithK(big1)
			Expect(err).Should(BeNil())
			responser.k = big.NewInt(0)
			responserMsg, err := responser.Handle(request.GetRequestMessage())
			Expect(err).Should(BeNil())
			got, err := request.Compute(responserMsg)
			Expect(got).Should(BeNil())
			Expect(err).Should(Equal(ErrIdentityPoint))
		})

		It("alpha : ErrInvalidPoint", func() {
			responser, err := NewResponser()
			Expect(err).Should(BeNil())
			responserMsg, err := responser.Handle(&OprfRequestMessage{})
			Expect(responserMsg).Should(BeNil())
			Expect(err).Should(Equal(pt.ErrInvalidPoint))
		})

		It("alpha : ErrIdentityPoint", func() {
			request, err := NewRequester([]byte("123"))
			Expect(err).Should(BeNil())
			request.requestMsg.Alpha, err = pt.NewIdentity(request.hashPW.GetCurve()).ToEcPointMessage()
			Expect(err).Should(BeNil())
			responser, err := NewResponser()
			Expect(err).Should(BeNil())
			responserMsg, err := responser.Handle(request.GetRequestMessage())
			Expect(responserMsg).Should(BeNil())
			Expect(err).Should(Equal(ErrIdentityPoint))
		})
	})
})

func TestOPRF(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "oprf Test")
}
