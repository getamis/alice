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
package peer

import (
	"context"
	"errors"
	"fmt"
	"math/rand"

	"github.com/getamis/sirius/log"
	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/helpers"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/multiformats/go-multiaddr"
)

// MakeBasicHost creates a LibP2P host.
func MakeBasicHost(port int64) (host.Host, error) {
	sourceMultiAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	if err != nil {
		return nil, err
	}

	priv, err := generateIdentity(port)
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

// getPeerAddr gets peer full address from port.
func getPeerAddr(port int64) (string, error) {
	priv, err := generateIdentity(port)
	if err != nil {
		return "", err
	}

	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s", port, pid), nil
}

// generateIdentity generates a fixed key pair by using port as random source.
func generateIdentity(port int64) (crypto.PrivKey, error) {
	// Use the port as the randomness source in this example.
	r := rand.New(rand.NewSource(port))

	// Generate a key pair for this host.
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.ECDSA, 2048, r)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// send sends the proto message to specified peer.
func send(ctx context.Context, host host.Host, target string, data interface{}, protocol protocol.ID) error {
	msg, ok := data.(proto.Message)
	if !ok {
		log.Warn("invalid proto message")
		return errors.New("invalid proto message")
	}
	// Turn the destination into a multiaddr.
	maddr, err := multiaddr.NewMultiaddr(target)
	if err != nil {
		log.Warn("Cannot parse the target address", "target", target, "err", err)
		return err
	}

	// Extract the peer ID from the multiaddr.
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Warn("Cannot parse addr", "addr", maddr, "err", err)
		return err
	}

	s, err := host.NewStream(ctx, info.ID, protocol)
	if err != nil {
		log.Warn("Cannot create a new stream", "from", host.ID(), "to", target, "err", err)
		return err
	}

	bs, err := proto.Marshal(msg)
	if err != nil {
		log.Warn("Cannot marshal message", "err", err)
		return err
	}

	_, err = s.Write(bs)
	if err != nil {
		log.Warn("Cannot write message to IO", "err", err)
		return err
	}
	err = helpers.FullClose(s)
	if err != nil {
		log.Warn("Cannot close the stream", "err", err)
		return err
	}

	log.Info("Sent message", "peer", target)
	return nil
}

// connect connects the host to the specified peer.
func connect(ctx context.Context, host host.Host, target string) error {
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
	err = host.Connect(ctx, *info)
	if err != nil {
		log.Warn("Failed to connect to peer", "err", err)
		return err
	}
	return nil
}
