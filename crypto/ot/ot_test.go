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

package ot

import (
	"bytes"
	"testing"

	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("OT test", func() {
	DescribeTable("basic OT", func(sid []byte, kappa int, ell int) {
		otrec, err := NewReceiver(sid, kappa, ell)
		Expect(err).Should(BeNil())
		otsend, err := NewSender(sid, otrec.GetReceiverMessage())
		Expect(err).Should(BeNil())
		otrecVerifyMsg, pib, err := otrec.Response(otsend.GetOtSenderMessage())
		Expect(err).Should(BeNil())
		Expect(pib).ShouldNot(BeNil())
		err = otsend.Veirfy(otrecVerifyMsg)
		Expect(err).Should(BeNil())
	},
		Entry("kappa:128, ell:100", []byte("adsfsdfs"), 128, 100),
	)

	DescribeTable("OT Extension", func(sid []byte, kappa int, m int) {
		a0 := make([][]byte, m)
		a1 := make([][]byte, m)
		rbit := make([]uint8, m)
		kappauint := kappa >> 3
		for i := 0; i < len(a0); i++ {
			a0byte, err := utils.GenRandomBytes(16)
			Expect(err).Should(BeNil())
			a1byte, err := utils.GenRandomBytes(16)
			Expect(err).Should(BeNil())
			a0[i] = padding(a0byte, kappauint)
			a1[i] = padding(a1byte, kappauint)
			tempr, err := utils.RandomInt(big2)
			Expect(err).Should(BeNil())
			if tempr.Cmp(big0) == 0 {
				rbit[i] = 0
			} else {
				rbit[i] = 1
			}
		}

		otExtS, err := NewExtSender(sid, kappa, a0, a1)
		Expect(err).Should(BeNil())
		otExtR, err := NewRecieverSeedOTPhase1(sid, rbit, otExtS.GetReceiverMessage())
		Expect(err).Should(BeNil())
		otExtSendResMsg, err := otExtS.Veirfy(otExtR.GetOtExtReceiveMessage())
		Expect(err).Should(BeNil())
		result, err := otExtR.GetOTFinalResult(otExtSendResMsg)
		Expect(err).Should(BeNil())
		for i := 0; i < len(otExtS.a0); i++ {
			if otExtR.r[i] == 0 {
				Expect(bytes.Equal(result[i], a0[i])).Should(BeTrue())
			} else {
				Expect(bytes.Equal(result[i], a1[i])).Should(BeTrue())
			}
		}
	},
		Entry("kappa:256, m: 768", []byte("adsfsdfs"), 128, 2048),
	)

})

func TestOT(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OT Test")
}
