// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package signer

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func TestSigner(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Signer Suite")
}

var (
	big2 = big.NewInt(2)
)

var _ = Describe("Signer", func() {
	var (
		testVector1, _ = new(big.Int).SetString("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", 16)
		testVector2, _ = new(big.Int).SetString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16)
		testVector3, _ = new(big.Int).SetString("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710", 16)
		testVector4, _ = new(big.Int).SetString("0340034003400340034003400340034003400340034003400340034003400340", 16)
	)

	DescribeTable("It should be OK", func(ss [][]*big.Int, privateKey *big.Int, curve elliptic.Curve) {
		expPublic := ecpointgrouplaw.ScalarBaseMult(curve, privateKey)
		threshold := len(ss)
		message := utils.Pad([]byte("8077818"), 32)
		numberShare := len(ss)
		Y := make([]*ecpointgrouplaw.ECPoint, numberShare)
		for i := 0; i < len(Y); i++ {
			Y[i] = ecpointgrouplaw.ScalarBaseMult(curve, ss[i][1])
		}
		signers, listeners := newSigners(curve, expPublic, ss, Y, message)
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

		for _, s := range signers {
			s.Start()
		}

		for i := 0; i < threshold; i++ {
			<-doneChs[i]
		}

		// Build public key
		var R *ecpointgrouplaw.ECPoint
		var s *big.Int
		for _, signer := range signers {
			signer.Stop()
			result, err := signer.GetResult()
			Expect(err).Should(BeNil())
			// All R and S should be the same
			if R != nil {
				Expect(R.Equal(result.R)).Should(BeTrue())
				Expect(s).Should(Equal(result.S))
			} else {
				R = result.R
				s = result.S
			}
		}
		Expect(Verify(expPublic, R, message, s)).Should(BeTrue())
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("(x-cooord, share, rank):f(x) = 2x+100", [][]*big.Int{
			{big.NewInt(1), big.NewInt(102), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(104), big.NewInt(0)},
			{big.NewInt(8), big.NewInt(116), big.NewInt(0)},
		}, big.NewInt(100), elliptic.Ed25519()),
		Entry("(x-cooord, share, rank):f(x) = 2x+100", [][]*big.Int{
			{big.NewInt(1), big.NewInt(102), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(104), big.NewInt(0)},
		}, big.NewInt(100), elliptic.Ed25519()),
		Entry("(x-cooord, share, rank):f(x) = x^2+5*x+1109", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1115), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(1123), big.NewInt(0)},
			{big.NewInt(50), big.NewInt(3859), big.NewInt(0)},
		}, big.NewInt(1109), elliptic.Ed25519()),
		Entry("(x-cooord, share, rank):f(x) = x^2+3*x+5555", [][]*big.Int{
			{big.NewInt(1), big.NewInt(5559), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(5565), big.NewInt(0)},
			{big.NewInt(50), big.NewInt(103), big.NewInt(1)},
		}, big.NewInt(5555), elliptic.Ed25519()),
		Entry("(x-cooord, share, rank):f(x) = 2*x^2+3*x+1111", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1116), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(4), big.NewInt(2)},
			{big.NewInt(50), big.NewInt(203), big.NewInt(1)},
		}, big.NewInt(1111), elliptic.Ed25519()),
		// Test Vector: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
		Entry("(x-cooord, share, rank):f(x) = 2*x^2+3*x+1111", [][]*big.Int{
			{big.NewInt(1), big.NewInt(1116), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(4), big.NewInt(2)},
			{big.NewInt(50), big.NewInt(203), big.NewInt(1)},
		}, big.NewInt(1111), elliptic.Secp256k1()),
		Entry("(x-cooord, share, rank):f(x) = x^2+3*x+5555", [][]*big.Int{
			{big.NewInt(1), big.NewInt(5559), big.NewInt(0)},
			{big.NewInt(2), big.NewInt(5565), big.NewInt(0)},
			{big.NewInt(50), big.NewInt(103), big.NewInt(1)},
		}, big.NewInt(5555), elliptic.Secp256k1()),
		Entry("(x-cooord, share, rank):f(x) = 5x+vector1", [][]*big.Int{
			{big.NewInt(1), new(big.Int).Add(testVector1, big.NewInt(5)), big.NewInt(0)},
			{big.NewInt(2), new(big.Int).Add(testVector1, big.NewInt(10)), big.NewInt(0)},
			{big.NewInt(8), new(big.Int).Add(testVector1, big.NewInt(40)), big.NewInt(0)},
		}, testVector1, elliptic.Secp256k1()),
		Entry("(x-cooord, share, rank):f(x) = 5x+vector2", [][]*big.Int{
			{big.NewInt(1), new(big.Int).Add(testVector2, big.NewInt(5)), big.NewInt(0)},
			{big.NewInt(2), new(big.Int).Add(testVector2, big.NewInt(10)), big.NewInt(0)},
			{big.NewInt(8), new(big.Int).Add(testVector2, big.NewInt(40)), big.NewInt(0)},
		}, testVector2, elliptic.Secp256k1()),
		Entry("(x-cooord, share, rank):f(x) = 7x+vector3", [][]*big.Int{
			{big.NewInt(1), new(big.Int).Add(testVector3, big.NewInt(7)), big.NewInt(0)},
			{big.NewInt(2), new(big.Int).Add(testVector3, big.NewInt(14)), big.NewInt(0)},
			{big.NewInt(8), new(big.Int).Add(testVector3, big.NewInt(56)), big.NewInt(0)},
		}, testVector3, elliptic.Secp256k1()),
		Entry("(x-cooord, share, rank):f(x) = x+vector4", [][]*big.Int{
			{big.NewInt(1), new(big.Int).Add(testVector4, big.NewInt(1)), big.NewInt(0)},
			{big.NewInt(2), new(big.Int).Add(testVector4, big.NewInt(2)), big.NewInt(0)},
			{big.NewInt(8), new(big.Int).Add(testVector4, big.NewInt(8)), big.NewInt(0)},
		}, testVector4, elliptic.Secp256k1()),
	)

	It("Verify failure case: computeB", func() {
		D := ecpointgrouplaw.ScalarBaseMult(elliptic.Ed25519(), big2)
		E := ecpointgrouplaw.ScalarBaseMult(elliptic.Secp256k1(), big2)
		got, err := computeB(nil, D, E)
		Expect(got).Should(BeNil())
		Expect(err).ShouldNot(BeNil())
	})
})

func newSigners(curve elliptic.Curve, expPublic *ecpointgrouplaw.ECPoint, ss [][]*big.Int, Y []*ecpointgrouplaw.ECPoint, msg []byte) (map[string]*Signer, map[string]*mocks.StateChangedListener) {
	threshold := len(ss)
	signers := make(map[string]*Signer, threshold)
	signersMain := make(map[string]types.MessageMain, threshold)
	peerManagers := make([]types.PeerManager, threshold)
	listeners := make(map[string]*mocks.StateChangedListener, threshold)

	bks := make(map[string]*birkhoffinterpolation.BkParameter, threshold)
	Ys := make(map[string]*ecpointgrouplaw.ECPoint, threshold)
	for i := 0; i < threshold; i++ {
		bks[tss.GetTestID(i)] = birkhoffinterpolation.NewBkParameter(ss[i][0], uint32(ss[i][2].Uint64()))
		Ys[tss.GetTestID(i)] = Y[i]
	}
	dkgData := &dkg.Result{
		Bks: bks,
		Ys:  Ys,
	}
	var err error
	for i := 0; i < threshold; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, threshold)
		pm.Set(signersMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		signers[id], err = NewSigner(expPublic, peerManagers[i], uint32(threshold), ss[i][1], dkgData, msg, listeners[id])
		Expect(err).Should(BeNil())
		signersMain[id] = signers[id]
		r, err := signers[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return signers, listeners
}

func Verify(pubKey, R *ecpointgrouplaw.ECPoint, message []byte, s *big.Int) bool {
	curveType := pubKey.GetCurve()
	switch curveType {
	case elliptic.Secp256k1():
		curveP := curveType.Params().P
		curveN := curveType.Params().N
		// Let P = lift_x(int(pk))
		Px, Py, err := liftX(pubKey.GetX(), curveType)
		if err != nil {
			return false
		}
		// Let r = int(sig[0:32]); fail if r ≥ p.
		r := new(big.Int).Set(R.GetX())
		if r.Cmp(curveP) >= 0 {
			return false
		}
		// Let s = int(sig[32:64]); fail if s ≥ n.
		s := new(big.Int).Set(s)
		if s.Cmp(curveN) >= 0 {
			return false
		}
		// Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
		toHash := utils.Bytes32(r)
		toHash = append(toHash, utils.Bytes32(Px)...)
		toHash = append(toHash, message...)
		e := new(big.Int).SetBytes(hash("BIPSchnorr", toHash))
		e.Mod(e, curveN)
		// Let R = s⋅G - e⋅P.
		RecoverPubKey, err := ecpointgrouplaw.NewECPoint(curveType, Px, Py)
		if err != nil {
			return false
		}
		R1 := ecpointgrouplaw.ScalarBaseMult(curveType, s)
		R2 := RecoverPubKey.ScalarMult(e)
		R2 = R2.Neg()
		compareR, err := R1.Add(R2)
		if err != nil {
			return false
		}
		// Fail if is_infinite(R).
		// Fail if not has_even_y(R).
		// Fail if x(R) ≠ r
		if compareR.IsIdentity() || !compareR.IsEvenY() || compareR.GetX().Cmp(r) != 0 {
			return false
		}
		return true

	case elliptic.Ed25519():
		edwardPubKey := edwards.NewPublicKey(edwards.Edwards(), pubKey.GetX(), pubKey.GetY())
		test1, err := ecpointEncoding(R)
		Expect(err).Should(BeNil())
		test2 := test1
		r := new(big.Int).SetBytes(utils.ReverseByte(test2[:]))
		return edwards.Verify(edwardPubKey, message, r, s)
	}
	return false
}

func liftX(x *big.Int, curve elliptic.Curve) (*big.Int, *big.Int, error) {
	curveP := curve.Params().P
	if x.Cmp(big0) == -1 || x.Cmp(curveP) == 1 {
		return nil, nil, ErrNotSupportCurve
	}
	compare := new(big.Int)
	compare.Exp(x, big.NewInt(3), curveP)
	compare.Add(compare, big.NewInt(7))
	compare.Mod(compare, curveP)
	exp := new(big.Int)
	exp.Add(curveP, big1)
	exp.Div(exp, big.NewInt(4))
	y := new(big.Int)
	y.Exp(compare, exp, curveP)
	ySquare := new(big.Int)
	ySquare.Exp(y, big2, curveP)
	if compare.Cmp(ySquare) != 0 {
		return nil, nil, ErrNotSupportCurve
	}
	if new(big.Int).And(y, big1).Cmp(big1) == 0 {
		y = y.Sub(curve.Params().P, y)
	}
	return x, y, nil
}

func hash(tag string, x []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	toHash := tagHash[:]
	toHash = append(toHash, tagHash[:]...)
	toHash = append(toHash, x...)
	hashed := sha256.Sum256(toHash)
	return utils.Pad(hashed[:], 32)
}
