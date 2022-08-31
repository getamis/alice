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

package childnewversion

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/bip32/validation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var (
	sid = []byte("adsfsdfs")
	p1, _ = new(big.Int).SetString("340366771288285996084147479119611242442614345594997750117006424456709538181213174956531242637348887020939489028407223567703089221775929476782718731241099422906757248077561707495116704707032100273066634958903193593316620328414148810945508298178558199690098617229620146557290778760832502595754641527561508212399", 10)
	q1, _ = new(big.Int).SetString("342210008150736860849172031711164446089742451413085875179968626169110229543810442993722803323695011123398437631091572923680081443255606910343772878832257779626343789749157295053728686888061039308352407604712625787390738281942368398061709210466176074618563526725844303576439528711252290452332401583658026307763", 10)
	p2, _ = new(big.Int).SetString("329524328382249319148628764796320840508305153692559642630478952397584014941151457067313849661756427706541392128829569820164488391545929472029591649023899042666372790978994596974957278845545627776319877812580448938383736549723272736985163607971865240447724733248007543186955586338718161415287240720736660379027", 10)
	q2, _ = new(big.Int).SetString("303257730957335372508990468184467952824893660405502046275411179022975791596082369116018636137081456229414107333744883072972870435672759889937021604516341631483943268195146188840571806143131404069249083788746474292239549553036812654888452038110307817556272081492401956345059506919164252213689045814591109663647", 10)
	paillierKeyA, _ = paillier.NewPaillierWithGivenPrimes(p1, q1)
	paillierKeyB, _ = paillier.NewPaillierWithGivenPrimes(p2, q2)
	pedA, _ = paillierKeyA.NewPedersenParameterByPaillier()
	pedB, _ = paillierKeyB.NewPedersenParameterByPaillier()
	aliceVad = validation.NewValidationManager(big.NewInt(0), paillierKeyA, pedA, pedB)
	bobVad = validation.NewValidationManager(big.NewInt(0), paillierKeyB, pedB, pedA)
)

var _ = Describe("Bip32 test", func() {
	DescribeTable("With seed", func(keyIndex int, seedString, expectedPrivate1 string, expectedChaincode1 string, expectedPrivate2 string, expectedChaincode2 string) {
		seed, err := hex.DecodeString(seedString)
		Expect(err).Should(BeNil())
		hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
		hmac512.Write(seed)
		hashResult := hmac512.Sum(nil)
		privateKey := new(big.Int).SetBytes(hashResult[0:32])
		chaincode := hashResult[32:]
		parentPubKey := pt.ScalarBaseMult(secp256k1, privateKey)
		childIndex := big.NewInt(int64(keyIndex))
		share1, _ := utils.RandomInt(curveN)
		share2 := new(big.Int).Sub(privateKey, share1)
		share2.Mod(share2, curveN)

		alice := NewParticipant(sid, share1, chaincode, childIndex, parentPubKey, 0, aliceVad)
		bob := NewParticipant(sid, share2, chaincode, childIndex, parentPubKey, 0, bobVad)

		aliceMsg1, err := alice.Round1()
		Expect(err).Should(BeNil())
		bobMsg1, err := bob.Round1()
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
		aliceChildShare, err := alice.Round6(bobMsg5, false)
		Expect(err).Should(BeNil())
		bobChildShare, err := bob.Round6(aliceMsg5, true)
		Expect(err).Should(BeNil())

		// validation test
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

		childPrivateKey := new(big.Int).Add(aliceChildShare.share, bobChildShare.share)
		childPrivateKey.Mod(childPrivateKey, curveN)
		anotherMethodChildParivateKey := new(big.Int).Add(privateKey, aliceChildShare.translate)
		anotherMethodChildParivateKey.Mod(anotherMethodChildParivateKey, curveN)
		Expect(anotherMethodChildParivateKey).Should(Equal(anotherMethodChildParivateKey))
		Expect(hex.EncodeToString(childPrivateKey.Bytes())).Should(Equal(expectedPrivate1))
		Expect(hex.EncodeToString(aliceChildShare.chainCode)).Should(Equal(expectedChaincode1))

		// m/ x'/1
		grandChildManager, err := aliceChildShare.ComputeNonHardenedChildShare(1)
		Expect(err).Should(BeNil())
		grandChildPrivateKey := new(big.Int).Add(grandChildManager.share, bobChildShare.share)
		grandChildPrivateKey.Mod(grandChildPrivateKey, curveN)
		Expect(hex.EncodeToString(grandChildPrivateKey.Bytes())).Should(Equal(expectedPrivate2))
		Expect(hex.EncodeToString(grandChildManager.chainCode)).Should(Equal(expectedChaincode2))
	},
		// ref : https://en.bitcoin.it/wiki/BIP_0032_TestVectors Vector 1.
		// ref : https://guggero.github.io/cryptography-toolkit/#!/hd-wallet Generating tools
		// ref : https://privatekeys.pw/calc Decoding tools
		FEntry("input:", 2147483648, "000102030405060708090a0b0c0d0e0f", "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368", "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"),
		Entry("input:", 2147483649, "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", "aa42a8995752603e297041a5497b656bb29cd2a408e78b6ca12c10af4ebca6be", "ebb9d4ba5b356ced5c9faa26c3f3ed14ea06450a1a07188c9b9e4ea32d0af7d1", "c0dd83e53578ac88e7bbcbb87e9ea6b25d96d0af671214e0fe4bd42bc505f690", "c1d90ec9ff1c6555472283b8609afae76a5718ef451e82c27310506e485f7adb"),
	)

	Measure("the benchmark performance of Periods.Subtract()", func(b Benchmarker) {
		seedString := "000102030405060708090a0b0c0d0e0f"
		keyIndex := 2147483648
		seed, err := hex.DecodeString(seedString)
		Expect(err).Should(BeNil())
		hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
		hmac512.Write(seed)
		hashResult := hmac512.Sum(nil)
		privateKey := new(big.Int).SetBytes(hashResult[0:32])
		chaincode := hashResult[32:]
		parentPubKey := pt.ScalarBaseMult(secp256k1, privateKey)
		childIndex := big.NewInt(int64(keyIndex))
		share1, _ := utils.RandomInt(curveN)
		share2 := new(big.Int).Sub(privateKey, share1)
		share2.Mod(share2, curveN)
		alice := NewParticipant(sid, share1, chaincode, childIndex, parentPubKey, 0, aliceVad)
		bob := NewParticipant(sid, share2, chaincode, childIndex, parentPubKey, 0, bobVad)

		runtime := b.Time("CKD Estimation", func() {
			aliceMsg1, err := alice.Round1()
			Expect(err).Should(BeNil())
			bobMsg1, err := bob.Round1()
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
			_, err = alice.Round6(bobMsg5, false)
			Expect(err).Should(BeNil())
			_, err = bob.Round6(aliceMsg5, true)
			Expect(err).Should(BeNil())

			// validation test
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
