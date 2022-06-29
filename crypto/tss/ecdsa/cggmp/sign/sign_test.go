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
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSign3Round(t *testing.T) {
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
		time.Sleep(2 * time.Second)
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
	ssidInfo := []byte("A")
	p1, _ := new(big.Int).SetString("340366771288285996084147479119611242442614345594997750117006424456709538181213174956531242637348887020939489028407223567703089221775929476782718731241099422906757248077561707495116704707032100273066634958903193593316620328414148810945508298178558199690098617229620146557290778760832502595754641527561508212399", 10)
	q1, _ := new(big.Int).SetString("342210008150736860849172031711164446089742451413085875179968626169110229543810442993722803323695011123398437631091572923680081443255606910343772878832257779626343789749157295053728686888061039308352407604712625787390738281942368398061709210466176074618563526725844303576439528711252290452332401583658026307763", 10)
	p2, _ := new(big.Int).SetString("329524328382249319148628764796320840508305153692559642630478952397584014941151457067313849661756427706541392128829569820164488391545929472029591649023899042666372790978994596974957278845545627776319877812580448938383736549723272736985163607971865240447724733248007543186955586338718161415287240720736660379027", 10)
	q2, _ := new(big.Int).SetString("303257730957335372508990468184467952824893660405502046275411179022975791596082369116018636137081456229414107333744883072972870435672759889937021604516341631483943268195146188840571806143131404069249083788746474292239549553036812654888452038110307817556272081492401956345059506919164252213689045814591109663647", 10)
	paillierKeyA, err := paillier.NewPaillierWithGivenPrimes(p1, q1)
	Expect(err).Should(BeNil())
	paillierKeyB, err := paillier.NewPaillierWithGivenPrimes(p2, q2)
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
	allPed := make(map[string]*paillierzkproof.PederssenOpenParameter)
	allPed[tss.GetTestID(0)] = pedA.PedersenOpenParameter
	allPed[tss.GetTestID(1)] = pedB.PedersenOpenParameter

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
