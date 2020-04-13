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
package service

import (
	"io/ioutil"

	"github.com/btcsuite/btcd/btcec"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/message/types"
	"github.com/getamis/alice/example/config"
	"github.com/getamis/alice/example/utils"
	"github.com/getamis/sirius/log"
	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
)

// For simplicity, we use S256 curve in this example.
var curve = btcec.S256()

type dkgService struct {
	config *config.Config
	pm     types.PeerManager

	dkg  *dkg.DKG
	done chan struct{}
}

func NewDKGService(config *config.Config, pm types.PeerManager) (*dkgService, error) {
	s := &dkgService{
		config: config,
		pm:     pm,
		done:   make(chan struct{}),
	}

	// Create dkg
	d, err := dkg.NewDKG(curve, pm, config.Threshold.DKG, config.Rank, s)
	if err != nil {
		log.Warn("Cannot create a new DKG", "config", config, "err", err)
		return nil, err
	}
	s.dkg = d
	return s, nil
}

func (p *dkgService) Handle(s network.Stream) {
	data := &dkg.Message{}
	buf, err := ioutil.ReadAll(s)
	if err != nil {
		log.Warn("Cannot read data from stream", "err", err)
		return
	}
	s.Close()

	// unmarshal it
	err = proto.Unmarshal(buf, data)
	if err != nil {
		log.Error("Cannot unmarshal data", "err", err)
		return
	}

	log.Info("Received request", "from", s.Conn().RemotePeer())
	err = p.dkg.AddMessage(data)
	if err != nil {
		log.Warn("Cannot add message to DKG", "err", err)
		return
	}
}

func (p *dkgService) Process() {
	// 1. Start a DKG process.
	p.dkg.Start()
	defer p.dkg.Stop()

	// 2. Connect the host to peers and send the peer message to them.
	msg := p.dkg.GetPeerMessage()
	for _, peerPort := range p.config.Peers {
		p.pm.MustSend(utils.GetPeerIDFromPort(peerPort), msg)
	}

	// 3. Wait the dkg is done or failed
	<-p.done
}

func (p *dkgService) OnStateChanged(oldState types.MainState, newState types.MainState) {
	if newState == types.StateFailed {
		log.Error("Dkg failed", "old", oldState.String(), "new", newState.String())
		close(p.done)
		return
	} else if newState == types.StateDone {
		log.Info("Dkg done", "old", oldState.String(), "new", newState.String())
		result, err := p.dkg.GetResult()
		if err == nil {
			utils.WriteDKGResult(p.pm.SelfID(), result)
		} else {
			log.Warn("Failed to get result from DKG", "err", err)
		}
		close(p.done)
		return
	}
	log.Info("State changed", "old", oldState.String(), "new", newState.String())
}
