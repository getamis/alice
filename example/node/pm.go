// Copyright © 2023 AMIS Technologies
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

package node

import (
	"context"
	"sync"
	"time"

	"github.com/getamis/sirius/log"
	"github.com/libp2p/go-libp2p-core/helpers"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

type peerManager struct {
	id       string
	host     host.Host
	protocol protocol.ID
	peers    map[string]string
	logger   log.Logger
}

func NewPeerManager(id string, host host.Host, protocol protocol.ID) *peerManager {
	return &peerManager{
		id:       id,
		host:     host,
		protocol: protocol,
		peers:    make(map[string]string),
		logger:   log.New(),
	}
}

func (p *peerManager) NumPeers() uint32 {
	return uint32(len(p.peers))
}

func (p *peerManager) SelfID() string {
	return p.id
}

func (p *peerManager) PeerIDs() []string {
	ids := make([]string, len(p.peers))
	i := 0
	for id := range p.peers {
		ids[i] = id
		i++
	}
	// sort.Strings(ids)
	return ids
}

func (p *peerManager) MustSend(peerId string, message interface{}) {
	msg, ok := message.(proto.Message)
	if !ok {
		p.logger.Warn("invalid proto message")
		return
	}

	target := p.peers[peerId]

	// Turn the destination into a multiaddr.
	maddr, err := multiaddr.NewMultiaddr(target)
	if err != nil {
		p.logger.Warn("Cannot parse the target address", "target", target, "err", err)
		return
	}

	// Extract the peer ID from the multiaddr.
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		p.logger.Warn("Cannot parse addr", "addr", maddr, "err", err)
		return
	}

	s, err := p.host.NewStream(context.Background(), info.ID, p.protocol)
	if err != nil {
		p.logger.Warn("Cannot create a new stream", "from", p.host.ID(), "to", info.ID, "protocol", p.protocol, "err", err)
		return
	}

	bs, err := proto.Marshal(msg)
	if err != nil {
		p.logger.Warn("Cannot marshal message", "err", err)
		return
	}

	_, err = s.Write(bs)
	if err != nil {
		p.logger.Warn("Cannot write message to IO", "err", err)
		return
	}

	err = helpers.FullClose(s)
	if err != nil {
		p.logger.Warn("Cannot close the stream", "err", err)
		return
	}

	log.Debug("Sent message", "peer", target)
}

// EnsureAllConnected connects the host to specified peer and sends the message to it.
func (p *peerManager) EnsureAllConnected() {
	var wg sync.WaitGroup

	// connect connects the host to the specified peer.
	connect := func(ctx context.Context, host host.Host, target string) error {
		// Turn the destination into a multiaddr.
		maddr, err := multiaddr.NewMultiaddr(target)
		if err != nil {
			p.logger.Warn("Cannot parse the target address", "target", target, "err", err)
			return err
		}

		// Extract the peer ID from the multiaddr.
		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			p.logger.Error("Cannot parse addr", "addr", maddr, "err", err)
			return err
		}

		// Connect the host to the peer.
		err = host.Connect(ctx, *info)
		if err != nil {
			// log.Warn("Failed to connect to peer", "err", err)
			return err
		}

		for {
			protocols, err := host.Peerstore().GetProtocols(info.ID)
			if err != nil {
				log.Warn("Failed to get peer protocols", "err", err)
			}

			for _, prootocol := range protocols {
				if prootocol == string(p.protocol) {
					return nil
				}
			}

			log.Debug("Waiting for peers")
			time.Sleep(2 * time.Second)
		}
	}

	for _, peerAddr := range p.peers {
		wg.Add(1)
		addr := peerAddr

		go func() {
			defer wg.Done()

			logger := log.New("peer", addr)
			for {
				// Connect the host to the peer.
				err := connect(context.Background(), p.host, addr)
				if err != nil {
					// logger.Warn("Failed to connect to peer", "err", err)
					time.Sleep(3 * time.Second)
					continue
				}
				logger.Info("Successfully connect to peer")
				return
			}
		}()
	}
	wg.Wait()
}

// AddPeer adds a peer to the peer list.
func (p *peerManager) AddPeer(peerId string, peerAddr string) {
	p.peers[peerId] = peerAddr
}
