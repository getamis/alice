package refresh

import (
	"bytes"
	"testing"

	"github.com/getamis/alice/crypto/zkproof/paillier"
)

func TestGetEchoMessage(t *testing.T) {
	tests := []struct {
		name     string
		msgType  Type
		wantEcho bool
	}{
		{name: "round 1", msgType: Type_Round1, wantEcho: true},
		{name: "round 2", msgType: Type_Round2, wantEcho: true},
		{name: "round 3 common proofs", msgType: Type_Round3, wantEcho: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := (&Message{Type: test.msgType, Id: "peer"}).GetEchoMessage()
			if (got != nil) != test.wantEcho {
				t.Fatalf("GetEchoMessage() = %v, want echo message: %t", got, test.wantEcho)
			}
			if !test.wantEcho {
				return
			}
			echo, ok := got.(*Message)
			if !ok || !echo.IsValid() || echo.GetId() != "peer" || echo.GetBody() != nil {
				t.Fatalf("GetEchoMessage() = %#v, want valid hash relay for peer", got)
			}
			wantHash, err := (&Message{Type: test.msgType, Id: "peer"}).CalculateEchoHash()
			if err != nil || !bytes.Equal(echo.GetEchoHash(), wantHash) {
				t.Fatalf("GetEchoMessage().EchoHash = %x, want %x (err = %v)", echo.GetEchoHash(), wantHash, err)
			}
		})
	}
}

func TestCalculateEchoHashBindsPublicRound3Fields(t *testing.T) {
	message := &Message{
		Type: Type_Round3,
		Id:   "peer",
		Body: &Message_Round3{Round3: &Round3Msg{ModProof: &paillier.PaillierBlumMessage{W: []byte("first")}}},
	}
	firstHash, err := message.CalculateEchoHash()
	if err != nil {
		t.Fatalf("CalculateEchoHash() error = %v", err)
	}

	message.GetRound3().ModProof.W = []byte("second")
	secondHash, err := message.CalculateEchoHash()
	if err != nil {
		t.Fatalf("CalculateEchoHash() error = %v", err)
	}
	if bytes.Equal(firstHash, secondHash) {
		t.Fatal("CalculateEchoHash() did not bind the round 3 proof")
	}
}

func TestCalculateEchoHashExcludesRound3Encshare(t *testing.T) {
	message := &Message{
		Type: Type_Round3,
		Id:   "peer",
		Body: &Message_Round3{Round3: &Round3Msg{Encshare: []byte("first recipient ciphertext")}},
	}
	firstHash, err := message.CalculateEchoHash()
	if err != nil {
		t.Fatalf("CalculateEchoHash() error = %v", err)
	}

	message.GetRound3().Encshare = []byte("second recipient ciphertext")
	secondHash, err := message.CalculateEchoHash()
	if err != nil {
		t.Fatalf("CalculateEchoHash() error = %v", err)
	}
	if !bytes.Equal(firstHash, secondHash) {
		t.Fatal("CalculateEchoHash() included receiver-specific Encshare")
	}
}
