package message_test

import (
	"testing"

	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	"github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
)

type relayTestPeerManager struct {
	peerIDs []string
}

func (p *relayTestPeerManager) MustSend(string, interface{}) {}

func (p *relayTestPeerManager) NumPeers() uint32 {
	return uint32(len(p.peerIDs))
}

func (p *relayTestPeerManager) PeerIDs() []string {
	return p.peerIDs
}

func (p *relayTestPeerManager) SelfID() string {
	return "self"
}

type relayTestMessageMain struct {
	received []types.Message
}

func (m *relayTestMessageMain) AddMessage(_ string, msg types.Message) error {
	m.received = append(m.received, msg)
	return nil
}

func (m *relayTestMessageMain) GetHandler() types.Handler {
	return nil
}

func (m *relayTestMessageMain) GetState() types.MainState {
	return types.StateInit
}

func (m *relayTestMessageMain) Start() {}

func (m *relayTestMessageMain) Stop() {}

func TestEchoRelayDoesNotReplaceOriginalMessage(t *testing.T) {
	original := &refresh.Message{
		Type: refresh.Type_Round3,
		Id:   "origin",
		Body: &refresh.Message_Round3{
			Round3: &refresh.Round3Msg{
				Encshare: []byte("recipient-specific ciphertext"),
			},
		},
	}
	relay := original.GetEchoMessage().(*refresh.Message)
	if !relay.IsEchoRelay() {
		t.Fatal("GetEchoMessage() did not mark relay message")
	}
	if len(relay.GetRound3().GetEncshare()) != 0 {
		t.Fatal("relay message contains recipient-specific ciphertext")
	}

	next := &relayTestMessageMain{}
	peerManager := &relayTestPeerManager{peerIDs: []string{"origin", "relay-peer"}}
	echoMain := message.NewEchoMsgMain(next, peerManager)

	if err := echoMain.AddMessage("relay-peer", relay); err != nil {
		t.Fatalf("AddMessage(relay) error = %v", err)
	}
	if len(next.received) != 0 {
		t.Fatalf("relay was delivered before original message: %#v", next.received)
	}

	if err := echoMain.AddMessage("origin", original); err != nil {
		t.Fatalf("AddMessage(original) error = %v", err)
	}
	if len(next.received) != 1 || next.received[0] != original {
		t.Fatalf("delivered message = %#v, want original complete message", next.received)
	}
	if got := next.received[0].(*refresh.Message).GetRound3().GetEncshare(); string(got) != "recipient-specific ciphertext" {
		t.Fatalf("delivered ciphertext = %q, want original recipient-specific ciphertext", got)
	}
}

func TestEchoRelayRequiresDistinctCanonicalVotes(t *testing.T) {
	original := &refresh.Message{
		Type: refresh.Type_Round3,
		Id:   "origin",
		Body: &refresh.Message_Round3{Round3: &refresh.Round3Msg{ModProof: &paillier.PaillierBlumMessage{W: []byte("proof")}}},
	}
	relay := original.GetEchoMessage().(*refresh.Message)
	next := &relayTestMessageMain{}
	peerManager := &relayTestPeerManager{peerIDs: []string{"origin", "relay-one", "relay-two"}}
	echoMain := message.NewEchoMsgMain(next, peerManager)

	if err := echoMain.AddMessage("relay-one", relay); err != nil {
		t.Fatalf("AddMessage(first relay) error = %v", err)
	}
	if err := echoMain.AddMessage("relay-one", relay); err != nil {
		t.Fatalf("AddMessage(duplicate relay) error = %v", err)
	}
	if err := echoMain.AddMessage("origin", original); err != nil {
		t.Fatalf("AddMessage(original) error = %v", err)
	}
	if len(next.received) != 0 {
		t.Fatalf("duplicate relay advanced quorum: %#v", next.received)
	}
	if err := echoMain.AddMessage("relay-two", relay); err != nil {
		t.Fatalf("AddMessage(second relay) error = %v", err)
	}
	if len(next.received) != 1 || next.received[0] != original {
		t.Fatalf("delivered messages = %#v, want original after all participant votes", next.received)
	}
}

func TestEchoRejectsConflictingRelayHash(t *testing.T) {
	original := &refresh.Message{
		Type: refresh.Type_Round3,
		Id:   "origin",
		Body: &refresh.Message_Round3{Round3: &refresh.Round3Msg{ModProof: &paillier.PaillierBlumMessage{W: []byte("proof")}}},
	}
	relay := original.GetEchoMessage().(*refresh.Message)
	relay.EchoHash[0] ^= 0xff
	next := &relayTestMessageMain{}
	peerManager := &relayTestPeerManager{peerIDs: []string{"origin", "relay"}}
	echoMain := message.NewEchoMsgMain(next, peerManager)

	if err := echoMain.AddMessage("origin", original); err != nil {
		t.Fatalf("AddMessage(original) error = %v", err)
	}
	if err := echoMain.AddMessage("relay", relay); err != message.ErrDifferentHash {
		t.Fatalf("AddMessage(conflicting relay) error = %v, want %v", err, message.ErrDifferentHash)
	}
}

func TestEchoCompletedInstanceRejectsConflictingLateMessage(t *testing.T) {
	original := &refresh.Message{
		Type: refresh.Type_Round3,
		Id:   "origin",
		Body: &refresh.Message_Round3{Round3: &refresh.Round3Msg{ModProof: &paillier.PaillierBlumMessage{W: []byte("proof")}}},
	}
	relay := original.GetEchoMessage().(*refresh.Message)
	next := &relayTestMessageMain{}
	peerManager := &relayTestPeerManager{peerIDs: []string{"origin", "relay"}}
	echoMain := message.NewEchoMsgMain(next, peerManager)

	if err := echoMain.AddMessage("relay", relay); err != nil {
		t.Fatalf("AddMessage(relay) error = %v", err)
	}
	if err := echoMain.AddMessage("origin", original); err != nil {
		t.Fatalf("AddMessage(original) error = %v", err)
	}
	if err := echoMain.AddMessage("origin", original); err != nil {
		t.Fatalf("AddMessage(late matching original) error = %v", err)
	}
	if len(next.received) != 1 {
		t.Fatalf("late matching original was delivered again: %#v", next.received)
	}

	conflicting := &refresh.Message{
		Type: refresh.Type_Round3,
		Id:   "origin",
		Body: &refresh.Message_Round3{Round3: &refresh.Round3Msg{ModProof: &paillier.PaillierBlumMessage{W: []byte("different-proof")}}},
	}
	if err := echoMain.AddMessage("origin", conflicting); err != message.ErrDifferentHash {
		t.Fatalf("AddMessage(late conflicting original) error = %v, want %v", err, message.ErrDifferentHash)
	}
}
