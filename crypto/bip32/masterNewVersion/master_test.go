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

package masternewversion

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/bip32/validation"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var (
	sid             = []byte("adsfsdfs")
	p1, _           = new(big.Int).SetString("340366771288285996084147479119611242442614345594997750117006424456709538181213174956531242637348887020939489028407223567703089221775929476782718731241099422906757248077561707495116704707032100273066634958903193593316620328414148810945508298178558199690098617229620146557290778760832502595754641527561508212399", 10)
	q1, _           = new(big.Int).SetString("342210008150736860849172031711164446089742451413085875179968626169110229543810442993722803323695011123398437631091572923680081443255606910343772878832257779626343789749157295053728686888061039308352407604712625787390738281942368398061709210466176074618563526725844303576439528711252290452332401583658026307763", 10)
	p2, _           = new(big.Int).SetString("329524328382249319148628764796320840508305153692559642630478952397584014941151457067313849661756427706541392128829569820164488391545929472029591649023899042666372790978994596974957278845545627776319877812580448938383736549723272736985163607971865240447724733248007543186955586338718161415287240720736660379027", 10)
	q2, _           = new(big.Int).SetString("303257730957335372508990468184467952824893660405502046275411179022975791596082369116018636137081456229414107333744883072972870435672759889937021604516341631483943268195146188840571806143131404069249083788746474292239549553036812654888452038110307817556272081492401956345059506919164252213689045814591109663647", 10)
	paillierKeyA, _ = paillier.NewPaillierWithGivenPrimes(p1, q1)
	paillierKeyB, _ = paillier.NewPaillierWithGivenPrimes(p2, q2)
	pedA, _         = paillierKeyA.NewPedersenParameterByPaillier()
	pedB, _         = paillierKeyB.NewPedersenParameterByPaillier()
	aliceVad        = validation.NewValidationManager(big.NewInt(0), paillierKeyA, pedA, pedB)
	bobVad          = validation.NewValidationManager(big.NewInt(0), paillierKeyB, pedB, pedA)
)

var _ = Describe("Bip32 test", func() {
	DescribeTable("With seed", func(seedstring, expected string) {
		seedByte, err := hex.DecodeString(seedstring)
		Expect(err).Should(BeNil())
		seed := utils.BytesToBits(seedByte)
		seed2, _ := utils.GenRandomBytes(64)
		seed2 = utils.BytesToBits(seed2)
		seed1 := utils.Xor(seed2, seed)
		alice := NewParticipant(sid, aliceVad)
		bob := NewParticipant(sid, bobVad)
		aliceMsg1, err := alice.Round1(seed1)
		Expect(err).Should(BeNil())
		bobMsg1, err := bob.Round1(seed2)
		Expect(err).Should(BeNil())
		aliceMsg2, err := alice.Round2(bobMsg1)
		Expect(err).Should(BeNil())
		bobMsg2, err := bob.Round2(aliceMsg1)
		Expect(err).Should(BeNil())
		aliceMsg3, err := alice.Round3(bobMsg2)
		Expect(err).Should(BeNil())
		bobMsg3, err := bob.Round3(aliceMsg2)
		Expect(err).Should(BeNil())
		aliceMsg4, err := alice.Round4(bobMsg3)
		Expect(err).Should(BeNil())
		bobMsg4, err := bob.Round4(aliceMsg3)
		Expect(err).Should(BeNil())
		aliceMsg5, err := alice.Round5(bobMsg4)
		Expect(err).Should(BeNil())
		bobMsg5, err := bob.Round5(aliceMsg4)
		Expect(err).Should(BeNil())

		// validation test: PubKey Q
		aliceVadMsg1, err := alice.validationManager.Round1()
		Expect(err).Should(BeNil())
		BobVadMsg2, err := bob.validationManager.Round2(aliceVadMsg1)
		Expect(err).Should(BeNil())
		err = alice.validationManager.Round3(BobVadMsg2)
		Expect(err).Should(BeNil())
		bobVadMsg1, err := bob.validationManager.Round1()
		Expect(err).Should(BeNil())
		aliceVadMsg2, err := alice.validationManager.Round2(bobVadMsg1)
		Expect(err).Should(BeNil())
		err = bob.validationManager.Round3(aliceVadMsg2)
		Expect(err).Should(BeNil())

		aliceShare, aliceI_R, err := alice.Round6(bobMsg5, false)
		Expect(err).Should(BeNil())
		bobShare, bobI_R, err := bob.Round6(aliceMsg5, true)
		Expect(err).Should(BeNil())

		// validation test: I_L+n1r2+n2r1 mod q
		aliceVadMsg1, err = alice.validationManager.Round1()
		Expect(err).Should(BeNil())
		BobVadMsg2, err = bob.validationManager.Round2(aliceVadMsg1)
		Expect(err).Should(BeNil())
		err = alice.validationManager.Round3(BobVadMsg2)
		Expect(err).Should(BeNil())
		bobVadMsg1, err = bob.validationManager.Round1()
		Expect(err).Should(BeNil())
		aliceVadMsg2, err = alice.validationManager.Round2(bobVadMsg1)
		Expect(err).Should(BeNil())
		err = bob.validationManager.Round3(aliceVadMsg2)
		Expect(err).Should(BeNil())

		privateKey := new(big.Int).Add(aliceShare, bobShare)
		privateKey.Mod(privateKey, curveN)
		expectedPrivateKey, _ := new(big.Int).SetString(expected[0:64], 16)
		Expect(privateKey.Cmp(expectedPrivateKey) == 0).Should(BeTrue())

		Expect(string(aliceI_R) == string(bobI_R)).Should(BeTrue())
		Expect(string(aliceI_R) == expected[64:]).Should(BeTrue())

	},
		FEntry("case1:", "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"),
	)

	Measure("the benchmark performance of Periods.Subtract()", func(b Benchmarker) {
		seedString := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
		seedByte, err := hex.DecodeString(seedString)
		Expect(err).Should(BeNil())
		seed := utils.BytesToBits(seedByte)
		seed2, _ := utils.GenRandomBytes(64)
		seed2 = utils.BytesToBits(seed2)
		seed1 := utils.Xor(seed2, seed)
		runtime := b.Time("MKG Estimation", func() {
			alice := NewParticipant(sid, aliceVad)
			bob := NewParticipant(sid, bobVad)
			aliceMsg1, err := alice.Round1(seed1)
			Expect(err).Should(BeNil())
			bobMsg1, err := bob.Round1(seed2)
			Expect(err).Should(BeNil())
			aliceMsg2, err := alice.Round2(bobMsg1)
			Expect(err).Should(BeNil())
			bobMsg2, err := bob.Round2(aliceMsg1)
			Expect(err).Should(BeNil())
			aliceMsg3, err := alice.Round3(bobMsg2)
			Expect(err).Should(BeNil())
			bobMsg3, err := bob.Round3(aliceMsg2)
			Expect(err).Should(BeNil())
			aliceMsg4, err := alice.Round4(bobMsg3)
			Expect(err).Should(BeNil())
			bobMsg4, err := bob.Round4(aliceMsg3)
			Expect(err).Should(BeNil())
			aliceMsg5, err := alice.Round5(bobMsg4)
			Expect(err).Should(BeNil())
			bobMsg5, err := bob.Round5(aliceMsg4)
			Expect(err).Should(BeNil())

			// validation test: PubKey Q
			aliceVadMsg1, err := alice.validationManager.Round1()
			Expect(err).Should(BeNil())
			BobVadMsg2, err := bob.validationManager.Round2(aliceVadMsg1)
			Expect(err).Should(BeNil())
			err = alice.validationManager.Round3(BobVadMsg2)
			Expect(err).Should(BeNil())
			bobVadMsg1, err := bob.validationManager.Round1()
			Expect(err).Should(BeNil())
			aliceVadMsg2, err := alice.validationManager.Round2(bobVadMsg1)
			Expect(err).Should(BeNil())
			err = bob.validationManager.Round3(aliceVadMsg2)
			Expect(err).Should(BeNil())

			_, _, err = alice.Round6(bobMsg5, false)
			Expect(err).Should(BeNil())
			_, _, err = bob.Round6(aliceMsg5, true)
			Expect(err).Should(BeNil())
			// validation test: I_L+n1r2+n2r1 mod q
			aliceVadMsg1, err = alice.validationManager.Round1()
			Expect(err).Should(BeNil())
			BobVadMsg2, err = bob.validationManager.Round2(aliceVadMsg1)
			Expect(err).Should(BeNil())
			err = alice.validationManager.Round3(BobVadMsg2)
			Expect(err).Should(BeNil())
			bobVadMsg1, err = bob.validationManager.Round1()
			Expect(err).Should(BeNil())
			aliceVadMsg2, err = alice.validationManager.Round2(bobVadMsg1)
			Expect(err).Should(BeNil())
			err = bob.validationManager.Round3(aliceVadMsg2)
			Expect(err).Should(BeNil())
		})

		Expect(runtime.Nanoseconds()).Should(BeNumerically("<", (100 * time.Second).Nanoseconds()))

		b.RecordValue("Execution time in microseconds", float64(runtime.Nanoseconds()/1000))
	},
		20)
})

func TestBip32(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Master Test")
}
