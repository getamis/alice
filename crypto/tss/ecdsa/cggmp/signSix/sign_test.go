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
package signSix

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
	"github.com/getamis/alice/types/message"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSign6Round(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SignSix Suite")
}

var (
	threshold       = uint32(2)
	secret          = big.NewInt(1)
	curve           = elliptic.Secp256k1()
	publicKey       = pt.ScalarBaseMult(curve, secret)
	msg             = []byte("Edwin HaHa")
	G               = pt.NewBase(curve)
	p1, _           = new(big.Int).SetString("340366771288285996084147479119611242442614345594997750117006424456709538181213174956531242637348887020939489028407223567703089221775929476782718731241099422906757248077561707495116704707032100273066634958903193593316620328414148810945508298178558199690098617229620146557290778760832502595754641527561508212399", 10)
	q1, _           = new(big.Int).SetString("342210008150736860849172031711164446089742451413085875179968626169110229543810442993722803323695011123398437631091572923680081443255606910343772878832257779626343789749157295053728686888061039308352407604712625787390738281942368398061709210466176074618563526725844303576439528711252290452332401583658026307763", 10)
	p2, _           = new(big.Int).SetString("329524328382249319148628764796320840508305153692559642630478952397584014941151457067313849661756427706541392128829569820164488391545929472029591649023899042666372790978994596974957278845545627776319877812580448938383736549723272736985163607971865240447724733248007543186955586338718161415287240720736660379027", 10)
	q2, _           = new(big.Int).SetString("303257730957335372508990468184467952824893660405502046275411179022975791596082369116018636137081456229414107333744883072972870435672759889937021604516341631483943268195146188840571806143131404069249083788746474292239549553036812654888452038110307817556272081492401956345059506919164252213689045814591109663647", 10)
	paillierKeyA, _ = paillier.NewPaillierWithGivenPrimes(p1, q1)
	paillierKeyB, _ = paillier.NewPaillierWithGivenPrimes(p2, q2)
	pedA, _         = paillierKeyA.NewPedersenParameterByPaillier()
	pedB, _         = paillierKeyB.NewPedersenParameterByPaillier()
	pedZKB          = paillierzkproof.NewPedersenOpenParameter(pedB.PedersenOpenParameter.Getn(), pedB.PedersenOpenParameter.Gets(), pedB.PedersenOpenParameter.Gett())
	pedZKA          = paillierzkproof.NewPedersenOpenParameter(pedA.PedersenOpenParameter.Getn(), pedA.PedersenOpenParameter.Gets(), pedA.PedersenOpenParameter.Gett())
)

var _ = Describe("SignSix", func() {
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

	It("Error1 handle: Should be OK", func() {
		ssidInfoWithBK := []byte("A")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		K1, rho1, err := paillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := paillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
		gamma1 := big.NewInt(11)
		gamma2 := big.NewInt(10)
		beta1 := big.NewInt(3)
		beta2 := big.NewInt(5)
		// P1 send K1 to P2, P2 chooses beta1 and P1 gets alpha1.
		alpha1 := new(big.Int).Mul(k1, gamma2)
		alpha1.Sub(alpha1, beta1)
		alpha2 := new(big.Int).Mul(k2, gamma1)
		alpha2.Sub(alpha2, beta2)
		D1 := computeD(gamma1, K2, beta1, pedZKB.Getn())
		D2 := computeD(gamma2, K1, beta2, pedZKA.Getn())
		delta1 := new(big.Int).Mul(k1, gamma1)
		delta1.Add(delta1, alpha1)
		delta1.Add(delta1, beta2)
		delta2 := new(big.Int).Mul(k2, gamma2)
		delta2.Add(delta2, alpha2)
		delta2.Add(delta2, beta1)
		ID1 := "ID-1"
		ID2 := "ID-2"
		peer1 := setPeerErr1(ssidInfoWithBK, pedZKA, D2, D1, gamma1, k2, K1, beta1, delta1, ID1)
		peer2 := setPeerErr1(ssidInfoWithBK, pedZKB, D1, D2, gamma2, k1, K2, beta2, delta2, ID2)
		map1 := make(map[string]*peer)
		map1[ID2] = peer2
		map2 := make(map[string]*peer)
		map2[ID1] = peer1

		p1Err := newRound5HandlerErr1(k1, gamma1, rho1, paillierKeyA, map1, ID1, peer1)
		p2Err := newRound5HandlerErr1(k2, gamma2, rho2, paillierKeyB, map2, ID2, peer2)
		err = p1Err.buildErr1Msg()
		Expect(err).Should(BeNil())
		err = p2Err.buildErr1Msg()
		Expect(err).Should(BeNil())
		errMsg1 := &Message{
			Id:   ID1,
			Type: Type_Err1,
			Body: p1Err.roundErr1Msg.Body,
		}
		errMsg2 := &Message{
			Id:   ID2,
			Type: Type_Err1,
			Body: p2Err.roundErr1Msg.Body,
		}
		ErrParticipant, err := p1Err.ProcessErr1Msg([]*Message{errMsg2})
		Expect(err).Should(BeNil())
		Expect(len(ErrParticipant) == 0).Should(BeTrue())
		ErrParticipant, err = p2Err.ProcessErr1Msg([]*Message{errMsg1})
		Expect(err).Should(BeNil())
		Expect(len(ErrParticipant) == 0).Should(BeTrue())
	})

	It("Error2 handle: Should be OK", func() {
		ssidInfoWithBK := []byte("B")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		b1 := big.NewInt(3)
		b2 := big.NewInt(10)
		y1 := big.NewInt(6)
		y2 := big.NewInt(13)
		Zb1G := G.ScalarMult(b1)
		Zb2G := G.ScalarMult(b2)
		Y1 := G.ScalarMult(y1)
		Y2 := G.ScalarMult(y2)
		K1, rho1, err := paillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := paillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
		x1 := big.NewInt(2)
		x2 := big.NewInt(3)
		bk1 := big.NewInt(2)
		bk2 := big.NewInt(-1)
		beta1 := big.NewInt(3)
		beta2 := big.NewInt(5)
		// P1 send K1 to P2, P2 chooses beta1 and P1 gets alpha1.
		alpha1 := new(big.Int).Mul(k1, x2)
		alpha1.Sub(alpha1, beta1)
		alpha2 := new(big.Int).Mul(k2, x1)
		alpha2.Sub(alpha2, beta2)
		D1 := computeD(x1, K2, beta1, pedZKB.Getn())
		D2 := computeD(x2, K1, beta2, pedZKA.Getn())
		chi1 := new(big.Int).Mul(k1, x1)
		chi1.Add(chi1, alpha1)
		chi1.Add(chi1, beta2)
		chi2 := new(big.Int).Mul(k2, x2)
		chi2.Add(chi2, alpha2)
		chi2.Add(chi2, beta1)
		Z2b1G := Y1.ScalarMult(b1)
		Z2b1G, err = Z2b1G.Add(G.ScalarMult(chi1))
		Expect(err).Should(BeNil())
		Z2b2G := Y2.ScalarMult(b2)
		Z2b2G, err = Z2b2G.Add(G.ScalarMult(chi2))
		Expect(err).Should(BeNil())
		ID1 := "ID-1"
		ID2 := "ID-2"
		peer1 := setPeerErr2(ssidInfoWithBK, pedZKA, D2, D1, x1, k2, K1, beta1, bk1, Zb1G, Z2b1G, Y1, ID1)
		peer2 := setPeerErr2(ssidInfoWithBK, pedZKB, D1, D2, x2, k1, K2, beta2, bk2, Zb2G, Z2b2G, Y2, ID2)
		map1 := make(map[string]*peer)
		map1[ID2] = peer2
		map2 := make(map[string]*peer)
		map2[ID1] = peer1
		p1Err := newRound6HandlerErr2(b1, k1, rho1, paillierKeyA, map1, ID1, peer1)
		p2Err := newRound6HandlerErr2(b2, k2, rho2, paillierKeyB, map2, ID2, peer2)
		err = p1Err.buildErr2Msg()
		Expect(err).Should(BeNil())
		err = p2Err.buildErr2Msg()
		Expect(err).Should(BeNil())
		errMsg1 := &Message{
			Id:   ID1,
			Type: Type_Err2,
			Body: p1Err.roundErr2Msg.Body,
		}
		errMsg2 := &Message{
			Id:   ID2,
			Type: Type_Err2,
			Body: p2Err.roundErr2Msg.Body,
		}
		ErrParticipant, err := p1Err.ProcessErr2Msg([]*Message{errMsg2})
		Expect(err).Should(BeNil())
		Expect(len(ErrParticipant) == 0).Should(BeTrue())
		ErrParticipant, err = p2Err.ProcessErr2Msg([]*Message{errMsg1})
		Expect(err).Should(BeNil())
		Expect(len(ErrParticipant) == 0).Should(BeTrue())
	})
})

func newSigns() (map[string]*Sign, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	ssidInfo := []byte("A")
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
	ySecret := []*big.Int{
		big.NewInt(100),
		big.NewInt(200),
	}
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(signsMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		signs[id], err = NewSign(threshold, ssidInfo, shares[i], ySecret[i], publicKey, partialPubKey, allY, bks, paillierKey[i], allPed, msg, peerManagers[i], listeners[id])
		Expect(err).Should(BeNil())
		signsMain[id] = signs[id]
		r, err := signs[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return signs, bks, listeners
}

func newRound5HandlerErr1(k, gamma, rho *big.Int, pailleirKey *paillier.Paillier, peers map[string]*peer, selfID string, ownPeer *peer) *round5Handler {
	p := &round1Handler{}
	p.rho = rho
	p.own = ownPeer
	p.paillierKey = pailleirKey
	p.k = k
	p.gamma = gamma
	p.peers = peers
	p.pubKey = publicKey
	p2, _ := newRound2Handler(p)
	p3, _ := newRound3Handler(p2)
	p4, _ := newRound4Handler(p3)
	p5, _ := newRound5Handler(p4)
	return p5
}

func computeD(gamma, K, beta, n *big.Int) *big.Int {
	nSquare := new(big.Int).Mul(n, n)
	d := new(big.Int).Exp(K, gamma, nSquare)
	encryption := new(big.Int).Exp(new(big.Int).Add(n, big1), beta, nSquare)
	salt := new(big.Int).Exp(big.NewInt(2), n, nSquare)
	d = d.Mul(encryption, d)
	d = d.Mul(d, salt)
	d.Mod(d, nSquare)
	return d
}

func setPeerErr1(ssidInfoWithBK []byte, para *paillierzkproof.PederssenOpenParameter, dround1, dround2, gamma, k, KOther, beta, delta *big.Int, ID string) *peer {
	alpha := new(big.Int).Mul(gamma, k)
	alpha.Add(alpha, beta)
	deta1 := &round1Data{
		kCiphertext: KOther,
		D:           dround1,
	}

	deta2 := &round2Data{
		d:     dround2,
		alpha: alpha,
	}
	deta3 := &round3Data{
		delta: delta,
	}

	deta4 := &round4Data{
		allGammaPoint: G.ScalarMult(gamma),
	}

	peer := &peer{
		Peer:       &message.Peer{Id: ID},
		ssidWithBk: ssidInfoWithBK,
		round1Data: deta1,
		round2Data: deta2,
		round3Data: deta3,
		round4Data: deta4,
		para:       para,
	}
	return peer
}

func setPeerErr2(ssidInfoWithBK []byte, para *paillierzkproof.PederssenOpenParameter, dround1, dround2, x, k, KOther, beta, bk *big.Int, z1, z2, Y *pt.ECPoint, ID string) *peer {
	alpha := new(big.Int).Mul(x, k)
	alpha.Add(alpha, beta)

	deta1 := &round1Data{
		kCiphertext: KOther,
		Dhat:        dround1.Bytes(),
	}

	deta2 := &round2Data{
		dhat:     dround2,
		alphahat: alpha,
	}
	deta3 := &round3Data{
		z1hat: z1,
		z2hat: z2,
	}

	peer := &peer{
		Peer:          &message.Peer{Id: ID},
		ssidWithBk:    ssidInfoWithBK,
		round1Data:    deta1,
		round2Data:    deta2,
		round3Data:    deta3,
		para:          para,
		allY:          Y,
		bkcoefficient: bk,
		partialPubKey: G.ScalarMult(x),
	}
	return peer
}

func newRound6HandlerErr2(bhat, k, rho *big.Int, pailleirKey *paillier.Paillier, peers map[string]*peer, selfID string, ownPeer *peer) *round6Handler {
	p := &round1Handler{}
	p.rho = rho
	p.paillierKey = pailleirKey
	p.k = k
	p.peers = peers
	p.pubKey = publicKey
	p.own = ownPeer
	p2, _ := newRound2Handler(p)
	p3, _ := newRound3Handler(p2)
	p4, _ := newRound4Handler(p3)
	p5, _ := newRound5Handler(p4)
	p6, _ := newRound6Handler(p5)
	p6.bhat = bhat
	return p6
}
