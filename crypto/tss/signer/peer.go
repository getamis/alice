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
	"github.com/aisuosuo/alice/internal/message"
)

type peer struct {
	*message.Peer
	pubkey       *pubkeyData
	enck         *encKData
	mta          *mtaData
	delta        *deltaData
	proofAi      *proofAiData
	commitViAi   *commitViAiData
	decommitViAi *decommitViAiData
	commitUiTi   *commitUiTiData
	decommitUiTi *decommitUiTiData
	si           *siData
}

func newPeer(id string) *peer {
	return &peer{
		Peer: message.NewPeer(id),
	}
}
