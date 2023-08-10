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

package paillier

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/utils"
	zkPaillier "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Paillier test", func() {
	var p *Paillier

	q, _ := new(big.Int).SetString("10336496840509889364743756728556894083875416095295273396941181548000513536258241829624621550248056598738200812136208483432747429613933803267341674099823747550457901792938534204209600816352455991030682178625461274696946412553495335169494161954275855961868018278909314518438942390349398230271383596573356141336290705904543749464743444571908925683808227763178673408886452417151633173952608404008495238645703427186230527122346924337193689116851298486127374649463968672143786586688944182483288520379761434290211175378957060058801139087249212625900662580046907927676806995810223144948951391774884485728735673277859673765328771775825894227833358913036583835896402644805494504684553222330561852974278994762349590002974821598192551606862894936008589747347955170171563906935369283687344097942382463286527986617015338161999294053722496648330919308826810988224866258639419015798823427778220374102703501296594463683201831136273499940851956029511479495854770947698140575124416299748352140192504575873322175343044571999461920996979455131764485117492329450789037039635142681758871861620633244854704748503667793164794519037537938222219889279030132358885519984583677240395400440328359216896636317956006026771966761427589473901417552919558629164382064291033649684050988936474375672855689408387541609529527339694118154800051353625824182962462155024805659873820081213620848343274742961393380326734167409982374755045790179293853420420960081635245599103068217862546127469694641255349533516949416195427585596186801827890931451843894239034939823027138359657335614133629070590454374946474344457190892568380822776317867340888645241715163317395260840400849523864570342718623052712234692433719368911685129848612737464946396867214378658668894418248328852037976143429021117537895706005880113908724921262590066258004690792767680699581022314494895139177488448572873567327785967376532877177582589422783335891303658383589640264480549450468455322233056185297427899476234959000297482159819255160686289493600858974734795517017156390693536928368734409794238246328652798661701533816199929405372249664833091930882681098822486625863941901579882342777822037410270350129659446368320183113627349994085195602951147949585477094769814057512441629974835214019250457587332217534304457199946192099697945513176448511749232945078903703963514268175887186162063324485470474850366779316479451903753793822221988927903013235888551998458367724039540044032835921689663631795600602677196676142758947390141755291955862916438206429", 10)
	pSquare := new(big.Int).Mul(q, q)

	BeforeEach(func() {
		var err error
		p, err = NewPaillier(3072)
		Expect(err).Should(BeNil())
	})

	It("implement homo.Crypto interface", func() {
		var _ homo.Crypto = p
	})

	FIt("implement homo.PubKey interface", func() {

		a, _ := utils.RandomInt(q)
		b, _ := utils.RandomInt(q)
		c := new(big.Int).Mul(a, b)
		new(big.Int).Exp(a, c, pSquare)
		//var _ homo.Pubkey = p.publicKey
	})

	It("GetMessageRange()", func() {
		n := big.NewInt(101)
		msgRange := new(big.Int).Sub(p.n, big.NewInt(10000))
		Expect(p.GetMessageRange(n)).Should(Equal(msgRange))
	})

	It("NewPaillier(): public key should be larger than 2048", func() {
		// The size key is small return the error.
		_, err := NewPaillier(2046)
		Expect(err).Should(Equal(ErrSmallPublicKeySize))
	})

	It("GetMessageRange()", func() {
		// always return nil
		Expect(p.VerifyEnc([]byte("enc"))).Should(BeNil())
	})

	It("GetN()", func() {
		Expect(p.publicKey.GetN()).ShouldNot(BeNil())
	})

	It("Getn()", func() {
		Expect(p.GetPubKey()).Should(Equal(p.publicKey))
	})

	It("NewPubKeyFromBytes(), invalid bytes", func() {
		msg := &pt.EcPointMessage{}
		bs, err := proto.Marshal(msg)
		Expect(err).Should(BeNil())
		got, err := p.NewPubKeyFromBytes(bs)
		Expect(err).ShouldNot(BeNil())
		Expect(got).Should(BeNil())
	})

	It("should be ok with valid random messages", func() {
		mInt, err := utils.RandomInt(p.publicKey.n)
		m := mInt.Bytes()
		Expect(err).Should(BeNil())
		c, err := p.Encrypt(m)
		Expect(err).Should(BeNil())
		Expect(c).ShouldNot(Equal(m))
		got, err := p.Decrypt(c)
		Expect(err).Should(BeNil())
		Expect(got).Should(Equal(m))

		By("Restore public key by message")
		bs := p.ToPubKeyBytes()
		pubkey, err := p.NewPubKeyFromBytes(bs)
		Expect(err).Should(BeNil())
		gotPub, ok := pubkey.(*publicKey)
		Expect(ok).Should(BeTrue())
		Expect(proto.Equal(p.publicKey.msg, gotPub.msg)).Should(BeTrue())
		Expect(p.publicKey.g).Should(Equal(gotPub.g))
		Expect(p.publicKey.n).Should(Equal(gotPub.n))
		Expect(p.publicKey.nSquare).Should(Equal(gotPub.nSquare))
	})

	It("should be ok with zero messages", func() {
		m := big0.Bytes()
		c, err := p.Encrypt(m)
		Expect(err).Should(BeNil())
		Expect(m).ShouldNot(Equal(c))
		got, err := p.Decrypt(c)
		Expect(err).Should(BeNil())
		Expect(m).Should(Equal(got))
	})

	It("should be ok with n-1", func() {
		m := new(big.Int).Sub(p.publicKey.n, big1).Bytes()
		c, err := p.Encrypt(m)
		Expect(err).Should(BeNil())
		Expect(c).ShouldNot(Equal(m))
		got, err := p.Decrypt(c)
		Expect(err).Should(BeNil())
		Expect(m).Should(Equal(got))
	})

	It("getter functions", func() {
		Expect(p.GetG()).Should(Equal(p.g))
		Expect(p.GetNSquare()).Should(Equal(p.nSquare))
	})

	Context("GetMtaProof()/VerifyMtaProof()", func() {
		curve := elliptic.Secp256k1()
		beta := big.NewInt(2)
		alpha := big.NewInt(12)
		b := big.NewInt(2)
		k := big.NewInt(5)
		It("should be ok", func() {
			bs, err := p.GetMtaProof(curve, beta, b)
			Expect(err).Should(BeNil())
			point, err := p.VerifyMtaProof(bs, curve, alpha, k)
			Expect(err).Should(BeNil())
			Expect(point.Equal(pt.ScalarBaseMult(curve, b))).Should(BeTrue())
		})

		It("invalid message bytes", func() {
			msg := &pt.EcPointMessage{
				X: []byte("X"),
			}
			bs, err := proto.Marshal(msg)
			Expect(err).Should(BeNil())

			p, err := p.VerifyMtaProof(bs, curve, alpha, k)
			Expect(err).ShouldNot(BeNil())
			Expect(p).Should(BeNil())
		})
	})

	Context("Invalid encrypt", func() {
		It("over range message", func() {
			c, err := p.Encrypt(p.publicKey.n.Bytes())
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(c).Should(BeNil())
		})
	})

	Context("Invalid decrypt", func() {
		It("over range message", func() {
			c, err := p.Decrypt(p.publicKey.n.Bytes())
			Expect(err).Should(Equal(ErrInvalidMessage))
			Expect(c).Should(BeNil())
		})

		It("zero message", func() {
			c, err := p.Decrypt(big0.Bytes())
			Expect(err).Should(Equal(utils.ErrNotInRange))
			Expect(c).Should(BeNil())
		})
	})

	DescribeTable("lFunction", func(x *big.Int, n *big.Int, exp *big.Int, expErr error) {
		got, gotErr := lFunction(x, n)
		if expErr != nil {
			Expect(gotErr).Should(Equal(expErr))
			Expect(got).Should(BeNil())
		} else {
			Expect(gotErr).Should(BeNil())
			Expect(got.Cmp(exp)).Should(BeZero())
		}
	},
		Entry("(12, 5) should be ok", big.NewInt(12), big.NewInt(5), big.NewInt(2), nil),
		Entry("(11, 5) should be ok", big.NewInt(11), big.NewInt(5), big.NewInt(2), nil),
		Entry("(1, 2) should be ok", big.NewInt(1), big.NewInt(2), big.NewInt(0), nil),
		Entry("(1, 1) should be ok", big.NewInt(1), big.NewInt(1), big.NewInt(0), nil),
		Entry("(0, 1) invalid input", big.NewInt(0), big.NewInt(1), nil, ErrInvalidInput),
		Entry("(1, 0) invalid input", big.NewInt(1), big.NewInt(0), nil, ErrInvalidInput),
		Entry("(-10, 1) invalid input", big.NewInt(-10), big.NewInt(1), nil, ErrInvalidInput),
	)

	DescribeTable("Add", func(m1 *big.Int, m2 *big.Int) {
		c1, err := p.Encrypt(m1.Bytes())
		Expect(err).Should(BeNil())
		c2, err := p.Encrypt(m2.Bytes())
		Expect(err).Should(BeNil())
		sum, err := p.publicKey.Add(c1, c2)
		Expect(err).Should(BeNil())
		decryptSum, err := p.Decrypt(sum)
		Expect(err).Should(BeNil())
		expected := new(big.Int).Add(m1, m2)
		Expect(decryptSum).Should(Equal(expected.Bytes()))
	},
		Entry("(100, 200)", big.NewInt(100), big.NewInt(200)),
		Entry("(0, 0)", big.NewInt(0), big.NewInt(0)),
		Entry("(0, 5)", big.NewInt(0), big.NewInt(5)),
		Entry("(9999, 200)", big.NewInt(9999), big.NewInt(200)),
	)

	DescribeTable("MulConst", func(m *big.Int, scalar *big.Int) {
		c, err := p.Encrypt(m.Bytes())
		Expect(err).Should(BeNil())
		mulConst, err := p.publicKey.MulConst(c, scalar)
		Expect(err).Should(BeNil())
		decryptResult, err := p.Decrypt(mulConst)
		Expect(err).Should(BeNil())
		expected := new(big.Int).Mul(m, scalar)
		Expect(decryptResult).Should(Equal(expected.Bytes()))
	},
		Entry("(10, 2)", big.NewInt(10), big.NewInt(2)),
		Entry("(9999, 21111)", big.NewInt(9999), big.NewInt(21111)),
		Entry("(9999, 0)", big.NewInt(9999), big.NewInt(0)),
		Entry("(0, 1)", big.NewInt(0), big.NewInt(1)),
		Entry("(0, 0)", big.NewInt(0), big.NewInt(0)),
	)

	Context("MulConst", func() {
		It("over Range, should be ok", func() {
			nMinis1 := new(big.Int).Sub(p.publicKey.n, big.NewInt(1))
			c, err := p.Encrypt(nMinis1.Bytes())
			Expect(err).Should(BeNil())
			scalar := new(big.Int).Sub(p.publicKey.n, big.NewInt(2))
			mulConst, err := p.publicKey.MulConst(c, scalar)
			Expect(err).Should(BeNil())
			decryptResult, err := p.Decrypt(mulConst)
			Expect(err).Should(BeNil())
			expected := new(big.Int).Mul(nMinis1, scalar)
			expected = expected.Mod(expected, p.publicKey.n)
			Expect(decryptResult).Should(Equal(expected.Bytes()))
		})

		It("zero c", func() {
			got, err := p.publicKey.MulConst(big0.Bytes(), big1)
			Expect(err).Should(Equal(utils.ErrNotInRange))
			Expect(got).Should(BeNil())
		})
	})

	Context("Add()", func() {
		It("over Range, should be ok", func() {
			nMinis1 := new(big.Int).Sub(p.publicKey.n, big.NewInt(1))
			c1, err := p.Encrypt(nMinis1.Bytes())
			Expect(err).Should(BeNil())
			nMinis2 := new(big.Int).Sub(p.publicKey.n, big.NewInt(2))
			c2, err := p.Encrypt(nMinis2.Bytes())
			Expect(err).Should(BeNil())
			sum, err := p.publicKey.Add(c1, c2)
			Expect(err).Should(BeNil())
			decryptResult, err := p.Decrypt(sum)
			Expect(err).Should(BeNil())
			expected := new(big.Int).Add(nMinis1, nMinis2)
			expected = expected.Mod(expected, p.publicKey.n)
			Expect(decryptResult).Should(Equal(expected.Bytes()))
		})

		It("zero c1", func() {
			got, err := p.publicKey.Add(big0.Bytes(), big1.Bytes())
			Expect(err).Should(Equal(utils.ErrNotInRange))
			Expect(got).Should(BeNil())
		})

		It("zero c2", func() {
			got, err := p.publicKey.Add(big1.Bytes(), big0.Bytes())
			Expect(err).Should(Equal(utils.ErrNotInRange))
			Expect(got).Should(BeNil())
		})
	})

	Context("pedersenparameter", func() {
		It("NewPedersenParameterByPaillier: it should be ok", func() {
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).Should(BeNil())
			Expect(ped).ShouldNot(BeNil())
		})

		It("negative p or q", func() {
			p.privateKey.q.Neg(p.privateKey.q)
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).ShouldNot(BeNil())
			Expect(ped).Should(BeNil())
		})

		It("negative n", func() {
			p.publicKey.n.Neg(p.publicKey.n)
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).ShouldNot(BeNil())
			Expect(ped).Should(BeNil())
		})

		It("get parameter:p , q, eulern, lambda: it should be ok", func() {
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).Should(BeNil())
			lambda := ped.Getlambda()
			Expect(lambda).ShouldNot(BeNil())
			p := ped.GetP()
			Expect(p).ShouldNot(BeNil())
			q := ped.GetQ()
			Expect(q).ShouldNot(BeNil())
			eulern := ped.eulern
			Expect(eulern).ShouldNot(BeNil())
		})

		It("NewPedersenOpenParameter: it should be ok", func() {
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).Should(BeNil())
			pedOpen, err := NewPedersenOpenParameter(ped.PedersenOpenParameter.Getn(), ped.PedersenOpenParameter.Gets(), ped.PedersenOpenParameter.Gett())
			Expect(err).Should(BeNil())
			Expect(pedOpen).ShouldNot(BeNil())
		})
		It("NewPedersenOpenParameter: s and n are not coprime", func() {
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).Should(BeNil())
			pedOpen, err := NewPedersenOpenParameter(ped.PedersenOpenParameter.Getn(), ped.PedersenOpenParameter.Getn(), ped.PedersenOpenParameter.Gett())
			Expect(err).ShouldNot(BeNil())
			Expect(pedOpen).Should(BeNil())
		})

		It("NewPedersenOpenParameter: t and n are not coprime", func() {
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).Should(BeNil())
			pedOpen, err := NewPedersenOpenParameter(ped.PedersenOpenParameter.Getn(), ped.PedersenOpenParameter.Gets(), ped.PedersenOpenParameter.Getn())
			Expect(err).ShouldNot(BeNil())
			Expect(pedOpen).Should(BeNil())
		})

		It("NewPedersenOpenParameter: bitlength of n is too small", func() {
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).Should(BeNil())
			pedOpen, err := NewPedersenOpenParameter(ped.GetP(), ped.PedersenOpenParameter.Gets(), ped.PedersenOpenParameter.Gett())
			Expect(err).ShouldNot(BeNil())
			Expect(pedOpen).Should(BeNil())
		})

		It("ToPaillierPubKeyWithSpecialG: it should be ok", func() {
			ped, err := p.NewPedersenParameterByPaillier()
			Expect(err).Should(BeNil())
			pedOpen, err := NewPedersenOpenParameter(ped.PedersenOpenParameter.Getn(), ped.PedersenOpenParameter.Gets(), ped.PedersenOpenParameter.Gett())
			Expect(err).Should(BeNil())
			pubKey := ToPaillierPubKeyWithSpecialG(pedOpen)
			Expect(pubKey).ShouldNot(BeNil())
		})

		It("ToPaillierPubKeyWithSpecialGFromMsg: bitlength of n is too small ", func() {
			msg := &zkPaillier.RingPederssenParameterMessage{
				N: big1.Bytes(),
			}
			pubKey, err := ToPaillierPubKeyWithSpecialGFromMsg(nil, msg)
			Expect(err).ShouldNot(BeNil())
			Expect(pubKey).Should(BeNil())
		})

		It("ToPaillierPubKeyWithSpecialGFromMsg: SSIDINFO is nil", func() {
			msg := &zkPaillier.RingPederssenParameterMessage{
				N: p.n.Bytes(),
			}
			pubKey, err := ToPaillierPubKeyWithSpecialGFromMsg(nil, msg)
			Expect(err).ShouldNot(BeNil())
			Expect(pubKey).Should(BeNil())
		})

		It("GetNthRoot: it should be ok", func() {
			nRoot, err := p.GetNthRoot()
			Expect(err).Should(BeNil())
			twoNPower := new(big.Int).Exp(big2, p.n, p.n)
			Expect(twoNPower.Exp(twoNPower, nRoot, p.n).Cmp(big2) == 0).Should(BeTrue())

		})

		It("GetNthRoot: negtive p", func() {
			p.privateKey.p.Neg(p.privateKey.p)
			nRoot, err := p.GetNthRoot()
			Expect(err).ShouldNot(BeNil())
			Expect(nRoot).Should(BeNil())
		})

		It("MulConst: negtive n", func() {
			p.publicKey.n.Neg(p.publicKey.n)
			msg, err := p.publicKey.MulConst([]byte("1"), big2)
			Expect(err).ShouldNot(BeNil())
			Expect(msg).Should(BeNil())
		})

		It("add: negtive n", func() {
			p.publicKey.n.Neg(p.publicKey.n)
			msg, err := p.publicKey.Add([]byte("1"), big2.Bytes())
			Expect(err).ShouldNot(BeNil())
			Expect(msg).Should(BeNil())
		})

		It("EncryptWithOutputSalt: negtive n", func() {
			p.publicKey.n.Neg(p.publicKey.n)
			c, r, err := p.publicKey.EncryptWithOutputSalt(big2)
			Expect(err).ShouldNot(BeNil())
			Expect(c).Should(BeNil())
			Expect(r).Should(BeNil())
		})

		It("getGAndMuWithSpecialG: negtive n", func() {
			p.publicKey.n.Neg(p.publicKey.n)
			g, mu, err := getGAndMuWithSpecialG(big2, p.publicKey.n)
			Expect(err).ShouldNot(BeNil())
			Expect(g).Should(BeNil())
			Expect(mu).Should(BeNil())
		})

		It("NewPaillierSafePrime: it should be ok", func() {
			key, err := NewPaillierSafePrime(safePubKeySize)
			Expect(err).Should(BeNil())
			p := key.privateKey.p
			q := key.privateKey.q
			Expect(p.ProbablyPrime(1)).Should(BeTrue())
			Expect(q.ProbablyPrime(1)).Should(BeTrue())
			pMinus1OverTwo := new(big.Int).Rsh(p, 1)
			qMinus1OverTwo := new(big.Int).Rsh(q, 1)
			Expect(pMinus1OverTwo.ProbablyPrime(1)).Should(BeTrue())
			Expect(qMinus1OverTwo.ProbablyPrime(1)).Should(BeTrue())
		})

		It("NewPaillierSafePrime: two small Privete key", func() {
			key, err := NewPaillierSafePrime(100)
			Expect(key).Should(BeNil())
			Expect(err).ShouldNot(BeNil())
		})

		It("NewPaillierWithGivenPrimes: it should be ok", func() {
			key, err := NewPaillierWithGivenPrimes(p.privateKey.p, p.privateKey.q)
			Expect(key).ShouldNot(BeNil())
			Expect(err).Should(BeNil())
		})

		It("NewPaillierWithGivenPrimes: negtive p", func() {
			key, err := NewPaillierWithGivenPrimes(new(big.Int).Neg(p.privateKey.p), p.privateKey.q)
			Expect(key).Should(BeNil())
			Expect(err).ShouldNot(BeNil())
		})

		It("NewPaillierWithGivenPrimes: p and q are the same", func() {
			key, err := NewPaillierWithGivenPrimes(p.privateKey.p, p.privateKey.p)
			Expect(key).Should(BeNil())
			Expect(err).ShouldNot(BeNil())
		})

		It("NewPaillierUnSafe: small key size", func() {
			p, err := NewPaillierUnSafe(1, true)
			Expect(p).Should(BeNil())
			Expect(err).ShouldNot(BeNil())
		})

		It("NewPaillierSafe: small key size", func() {
			p, err := NewPaillierUnSafe(1, false)
			Expect(p).Should(BeNil())
			Expect(err).ShouldNot(BeNil())
		})

		It("decypt: negative n", func() {
			p.publicKey.n.Neg(p.publicKey.n)
			plaintext, err := p.Decrypt(big2.Bytes())
			Expect(plaintext).Should(BeNil())
			Expect(err).ShouldNot(BeNil())
		})
	})
})

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Crypto Test")
}
