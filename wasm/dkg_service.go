// +build js,wasm
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

package main

import (
	"errors"
	"syscall/js"

	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/message/types"
)

// Global variable
var srv *dkgService

type dkgService struct {
	*dkg.DKG
	resultCallback js.Value
}

func NewDKGService(password []byte, pm types.PeerManager, resultCallback js.Value) (*dkgService, error) {
	s := &dkgService{
		resultCallback: resultCallback,
	}
	// Create dkg
	d, err := dkg.NewPasswordUserDKG(pm, s, password)
	if err != nil {
		return nil, err
	}
	s.DKG = d
	return s, nil
}

func (p *dkgService) OnStateChanged(oldState types.MainState, newState types.MainState) {
	if newState == types.StateFailed {
		p.resultCallback.Invoke(toJSError(errors.New("DKG failed")), nil)
		p.Stop()
		return
	} else if newState == types.StateDone {
		_, err := p.DKG.GetResult()
		if err == nil {
			// Not send out the result for now
			// bkMap := make(map[string]interface{})
			// dkgResult := map[string]interface{}{
			// 	"share": result.Share.String(),
			// 	"pubkey": map[string]interface{}{
			// 		"x": result.PublicKey.GetX().String(),
			// 		"y": result.PublicKey.GetY().String(),
			// 	},
			// 	"bks": bkMap,
			// }
			// for peerID, bk := range result.Bks {
			// 	bkMap[peerID] = map[string]interface{}{
			// 		"x":    bk.GetX().String(),
			// 		"rank": bk.GetRank(),
			// 	}
			// }
			p.resultCallback.Invoke(js.Null(), "ok")
		} else {
			p.resultCallback.Invoke(toJSError(err), nil)
		}
		p.Stop()
		return
	}
}
