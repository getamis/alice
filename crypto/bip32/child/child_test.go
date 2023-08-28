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

package child

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

const (
	circuitPtah = "../../circuit/bristolFashion/MPCHMAC.txt"
)

var _ = Describe("Child test", func() {
	DescribeTable("Harden", func(expectedPrivate1 string, expectedChaincode1 string, expectedPrivate2 string, expectedChaincode2 string) {
		sid := []byte("13415313135")
		threshold := uint32(2)
		seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
		Expect(err).Should(BeNil())
		hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
		hmac512.Write(seed)
		hashResult := hmac512.Sum(nil)
		privateKey := new(big.Int).SetBytes(hashResult[0:32])
		chaincode := hashResult[32:]
		pubKey := ecpointgrouplaw.ScalarBaseMult(curve, privateKey)
		x1, err := utils.RandomPositiveInt(curve.Params().N)
		Expect(err).Should(BeNil())
		x2, err := utils.RandomPositiveInt(curve.Params().N)
		Expect(err).Should(BeNil())

		poly, err := polynomial.RandomPolynomial(curve.Params().N, threshold-1)
		Expect(err).Should(BeNil())
		poly.SetConstant(privateKey)
		share1 := poly.Evaluate(x1)
		share2 := poly.Evaluate(x2)
		// share1: rank 0 and share2: rank 0
		share1.Mod(share1, curve.Params().N)
		share2.Mod(share2, curve.Params().N)
		childIndex := uint32(2147483648)

		bksMap := map[string]*birkhoffinterpolation.BkParameter{
			"id-0": birkhoffinterpolation.NewBkParameter(x1, 0),
			"id-1": birkhoffinterpolation.NewBkParameter(x2, 0),
		}

		children, listeners := newChildren(sid, []*big.Int{
			share1,
			share2,
		}, bksMap, chaincode, 0, childIndex, pubKey)
		doneChs := make([]chan struct{}, threshold)
		i := 0
		for _, l := range listeners {
			doneChs[i] = make(chan struct{})
			doneCh := doneChs[i]
			l.On("OnStateChanged", types.StateInit, types.StateDone).Run(func(args mock.Arguments) {
				close(doneCh)
			}).Once()
			i++
		}

		for _, s := range children {
			s.Start()
		}
		for _, ch := range doneChs {
			<-ch
		}

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		// m0'
		var childTranslate *big.Int
		var childShares []*childShare
		for _, s := range children {
			h, ok := s.GetHandler().(*sh2Hash)
			Expect(ok).Should(BeTrue())
			if childTranslate == nil {
				childTranslate = h.childShare.translate
			} else {
				Expect(childTranslate).Should(Equal(h.childShare.translate))
			}
			childShares = append(childShares, h.childShare)
		}

		bbks := make(birkhoffinterpolation.BkParameters, 2)
		bbks[0] = birkhoffinterpolation.NewBkParameter(x1, 0)
		bbks[1] = birkhoffinterpolation.NewBkParameter(x2, 0)
		cos, err := bbks.ComputeBkCoefficient(2, secp256k1N)
		Expect(err).Should(BeNil())
		childshare1 := new(big.Int).Mul(cos[0], childShares[0].share)
		childshare2 := new(big.Int).Mul(cos[1], childShares[1].share)
		childPrivateKey := new(big.Int).Add(childshare1, childshare2)
		childPrivateKey.Mod(childPrivateKey, curve.Params().N)
		anotherMethodChildParivateKey := new(big.Int).Add(privateKey, childTranslate)
		anotherMethodChildParivateKey.Mod(anotherMethodChildParivateKey, curve.Params().N)
		Expect(anotherMethodChildParivateKey).Should(Equal(anotherMethodChildParivateKey))
		Expect(hex.EncodeToString(childPrivateKey.Bytes())).Should(Equal(expectedPrivate1))
		Expect(hex.EncodeToString(childShares[0].chainCode)).Should(Equal(expectedChaincode1))
		Expect(hex.EncodeToString(childShares[1].chainCode)).Should(Equal(expectedChaincode1))
		childPubKey := ecpointgrouplaw.ScalarBaseMult(curve, childPrivateKey)
		Expect(childPubKey.Equal(childShares[0].publicKey)).Should(BeTrue())
		Expect(childShares[0].publicKey.Equal(childShares[1].publicKey)).Should(BeTrue())

		// m0'/1 (Modify by Birkhoff Coefficient)
		grandChildManager1, err := childShares[0].ComputeNonHardenedChildShare(1)
		Expect(err).Should(BeNil())
		grandChildManager2, err := childShares[1].ComputeNonHardenedChildShare(1)
		Expect(err).Should(BeNil())
		childShare1 := new(big.Int).Mul(cos[0], grandChildManager1.share)
		childShare2 := new(big.Int).Mul(cos[1], grandChildManager2.share)
		grandChildPrivateKey := new(big.Int).Add(childShare1, childShare2)
		grandChildPrivateKey.Mod(grandChildPrivateKey, curve.Params().N)
		Expect(hex.EncodeToString(grandChildPrivateKey.Bytes())).Should(Equal(expectedPrivate2))
		Expect(hex.EncodeToString(grandChildManager1.chainCode)).Should(Equal(expectedChaincode2))
		Expect(hex.EncodeToString(grandChildManager2.chainCode)).Should(Equal(expectedChaincode2))
		grandChildPubKey := ecpointgrouplaw.ScalarBaseMult(curve, grandChildPrivateKey)
		Expect(grandChildPubKey.Equal(grandChildManager1.publicKey)).Should(BeTrue())
		Expect(grandChildManager2.publicKey.Equal(grandChildManager1.publicKey)).Should(BeTrue())
	},
		// ref : https://en.bitcoin.it/wiki/BIP_0032_TestVectors Vector 1.
		XEntry("input:", "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368", "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"),
	)
})

func TestChild(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Child Test")
}

func newChildren(sid []uint8, shares []*big.Int, bks map[string]*birkhoffinterpolation.BkParameter, chainCode []byte, depth uint8, childIndex uint32, pubKey *ecpointgrouplaw.ECPoint) (map[string]*Child, map[string]*mocks.StateChangedListener) {
	lens := len(shares)
	children := make(map[string]*Child, lens)
	childrenMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)

	for i := 0; i < len(shares); i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(childrenMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		if i == 0 {
			children[id], err = NewAlice(peerManagers[i], sid, shares[i], bks, circuitPtah, chainCode, depth, childIndex, pubKey, listeners[id])
			Expect(err).Should(BeNil())
		} else if i == 1 {
			children[id], err = NewBob(peerManagers[i], sid, shares[i], bks, circuitPtah, chainCode, depth, childIndex, pubKey, listeners[id])
			Expect(err).Should(BeNil())
		}

		childrenMain[id] = children[id]
	}
	return children, listeners
}
