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
	"context"
	"fmt"
	"math/rand"

	"github.com/getamis/sirius/log"
	ggio "github.com/gogo/protobuf/io"
	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/helpers"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
)

// makeBasicHost creates a LibP2P host.
func makeBasicHost(port uint64) (host.Host, error) {
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))

	// Use the port number as the randomness source.
	r := rand.New(rand.NewSource(int64(port)))

	// Generate a key pair for this host. We will use it at least
	// to obtain a valid host ID.
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.ECDSA, 2048, r)
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(priv),
	}

	basicHost, err := libp2p.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	return basicHost, nil
}

// send sends the proto message to specified peer.
func send(host host.Host, target string, data proto.Message) error {
	// Turn the destination into a multiaddr.
	maddr, err := multiaddr.NewMultiaddr(target)
	if err != nil {
		log.Warn("Cannot parse the target address", "target", target, "err", err)
		return err
	}

	// Extract the peer ID from the multiaddr.
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Error("Cannot parse addr", "addr", maddr, "err", err)
		return err
	}

	s, err := host.NewStream(context.Background(), info.ID, dkgProtocol)
	if err != nil {
		log.Warn("Cannot create a new stream", "from", host.ID(), "to", target, "err", err)
		return err
	}
	writer := ggio.NewFullWriter(s)
	err = writer.WriteMsg(data)
	if err != nil {
		log.Warn("Cannot write message to IO", "err", err)
		s.Reset()
		return err
	}
	err = helpers.FullClose(s)
	if err != nil {
		log.Warn("Cannot close the stream", "err", err)
		s.Reset()
		return err
	}

	log.Info("Sent message", "peer", target)
	return nil
}

// connect connects the host to the specified peer.
func connect(host host.Host, target string) error {
	// Turn the destination into a multiaddr.
	maddr, err := multiaddr.NewMultiaddr(target)
	if err != nil {
		log.Warn("Cannot parse the target address", "target", target, "err", err)
		return err
	}

	// Extract the peer ID from the multiaddr.
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Error("Cannot parse addr", "addr", maddr, "err", err)
		return err
	}

	// Connect the host to the peer.
	err = host.Connect(context.Background(), *info)
	if err != nil {
		log.Warn("Failed to connect to peer", "err", err)
		return err
	}
	return nil
}
