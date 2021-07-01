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
package signer

import (
	"crypto/ecdsa"
	"math/big"
	"time"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/password/reshare"
	"github.com/getamis/alice/crypto/tss/password/verifier"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/alice/internal/message/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

const (
	oldPassword = "edwin-haha"
	newPassword = "cy-haha"
)

var _ = Describe("Password Tests", func() {
	DescribeTable("should be ok", func(homoFunc func() (homo.Crypto, error)) {
		By("Step 1: DKG")
		password := []byte(oldPassword)
		dkgs, listeners := newPasswordDKGs(password)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, d := range dkgs {
			d.Start()
		}
		time.Sleep(1 * time.Second)

		// Stop DKG process and record the result.
		for _, dkg := range dkgs {
			dkg.Stop()
		}
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		By("Step 2: Signer")
		msg := []byte("1234567")
		homo, err := homoFunc()
		Expect(err).Should(BeNil())
		expPublic, ss, listeners := newPasswordSigners(password, dkgs, homo, msg)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, s := range ss {
			s.Start()
		}
		time.Sleep(2 * time.Second)

		// Build public key
		var r *ecpointgrouplaw.ECPoint
		var s *big.Int
		for _, signer := range ss {
			signer.Stop()
			result, err := signer.GetResult()
			Expect(err).Should(BeNil())
			// All R and S should be the same
			if r != nil {
				Expect(r).Should(Equal(result.R))
				Expect(s).Should(Equal(result.S))
			} else {
				r = result.R
				s = result.S
			}
		}
		Expect(ecdsa.Verify(expPublic.ToPubKey(), msg, r.GetX(), s)).Should(BeTrue())

		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		By("Step 3: Verifer")
		urV, srV, listeners := newPasswordVerifiers([]byte(oldPassword), dkgs)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		srV.Start()
		urV.Start()
		time.Sleep(2 * time.Second)
		// Stop verifer process.
		srV.Stop()
		urV.Stop()
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		By("Step 4: Reshare")
		ur, sr, listeners := newPasswordReshares([]byte(oldPassword), []byte(newPassword), dkgs)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		sr.Start()
		ur.Start()
		time.Sleep(2 * time.Second)
		// Stop reshare process.
		sr.Stop()
		ur.Stop()
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("paillier", func() (homo.Crypto, error) {
			return paillier.NewPaillier(2048)
		}),
	)

	DescribeTable("wrong password", func(homoFunc func() (homo.Crypto, error)) {
		By("Step 1: DKG")
		password := []byte("edwin-haha")
		dkgs, listeners := newPasswordDKGs(password)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Once()
		}
		for _, d := range dkgs {
			d.Start()
		}
		time.Sleep(2 * time.Second)

		// Stop DKG process and record the result.
		for _, dkg := range dkgs {
			dkg.Stop()
		}
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}

		By("Step 2: Signer")
		msg := []byte("1234567")
		homo, err := homoFunc()
		Expect(err).Should(BeNil())
		_, ss, listeners := newPasswordSigners([]byte("wrong password"), dkgs, homo, msg)
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
		}
		for _, s := range ss {
			s.Start()
		}
		time.Sleep(1 * time.Second)

		// Build public key
		for _, signer := range ss {
			Expect(tss.IsWrongPasswordError(signer.GetFinalError())).Should(BeTrue())
		}
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
	},
		Entry("paillier", func() (homo.Crypto, error) {
			return paillier.NewPaillier(2048)
		}),
	)
})

func newPasswordDKGs(password []byte) (map[string]*dkg.DKG, map[string]*mocks.StateChangedListener) {
	lens := 2
	dkgs := make(map[string]*dkg.DKG, lens)
	dkgsMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(dkgsMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		if i == 0 {
			dkgs[id], err = dkg.NewPasswordUserDKG(peerManagers[i], listeners[id], password)
		} else {
			dkgs[id], err = dkg.NewPasswordServerDKG(peerManagers[i], listeners[id])
		}
		Expect(err).Should(BeNil())
		dkgsMain[id] = dkgs[id]
		r, err := dkgs[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return dkgs, listeners
}

func newPasswordSigners(password []byte, dkgs map[string]*dkg.DKG, homo homo.Crypto, msg []byte) (*ecpointgrouplaw.ECPoint, map[string]*Signer, map[string]*mocks.StateChangedListener) {
	lens := 2
	ss := make(map[string]*Signer, lens)
	ssMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	var pubKey *ecpointgrouplaw.ECPoint
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(ssMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		d := dkgs[id]
		r, err := d.GetResult()
		Expect(err).Should(BeNil())
		if i == 0 {
			ss[id], err = NewPasswordUserSigner(pm, r.PublicKey, homo, password, r.Bks, msg, listeners[id])
		} else {
			ss[id], err = NewPasswordServerSigner(pm, r.PublicKey, homo, r.K, r.Share, r.Bks, msg, listeners[id])
		}
		Expect(err).Should(BeNil())
		ssMain[id] = ss[id]
		pubKey = r.PublicKey
	}
	return pubKey, ss, listeners
}

func newPasswordReshares(oldPassword []byte, newPassword []byte, dkgs map[string]*dkg.DKG) (*reshare.UserReshare, *reshare.ServerReshare, map[string]*mocks.StateChangedListener) {
	var (
		ur *reshare.UserReshare
		sr *reshare.ServerReshare
	)
	lens := 2
	ssMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(ssMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		r, err := dkgs[id].GetResult()
		Expect(err).Should(BeNil())
		if i == 0 {
			ur, err = reshare.NewUserReshare(pm, r.PublicKey, oldPassword, newPassword, r.Bks, listeners[id])
			ssMain[id] = ur
		} else {
			sr, err = reshare.NewServerReshare(pm, r.PublicKey, r.K, r.Share, r.Bks, listeners[id])
			ssMain[id] = sr
		}
		Expect(err).Should(BeNil())
	}
	return ur, sr, listeners
}

func newPasswordVerifiers(oldPassword []byte, dkgs map[string]*dkg.DKG) (*verifier.UserVerifier, *verifier.ServerVerifier, map[string]*mocks.StateChangedListener) {
	var (
		ur *verifier.UserVerifier
		sr *verifier.ServerVerifier
	)
	lens := 2
	ssMain := make(map[string]types.MessageMain, lens)
	peerManagers := make([]types.PeerManager, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		pm := tss.NewTestPeerManager(i, lens)
		pm.Set(ssMain)
		peerManagers[i] = pm
		listeners[id] = new(mocks.StateChangedListener)
		r, err := dkgs[id].GetResult()
		Expect(err).Should(BeNil())
		if i == 0 {
			ur, err = verifier.NewUserVerifier(pm, r.PublicKey, oldPassword, r.Bks, listeners[id])
			ssMain[id] = ur
		} else {
			sr, err = verifier.NewServerVerifier(pm, r.PublicKey, r.K, r.Share, r.Bks, listeners[id])
			ssMain[id] = sr
		}
		Expect(err).Should(BeNil())
	}
	return ur, sr, listeners
}
