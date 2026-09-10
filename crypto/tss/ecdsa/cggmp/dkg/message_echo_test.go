package dkg

import (
	"bytes"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
)

func TestGetEchoMessage(t *testing.T) {
	tests := []struct {
		name     string
		msgType  Type
		wantEcho bool
	}{
		{name: "peer", msgType: Type_Peer, wantEcho: true},
		{name: "decommit", msgType: Type_Decommit, wantEcho: true},
		{name: "verify", msgType: Type_Verify, wantEcho: false},
		{name: "result", msgType: Type_Result, wantEcho: true},
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
			if !ok || !echo.IsValid() || echo.GetId() != "peer" || len(echo.GetEchoHash()) != 32 || echo.GetBody() != nil {
				t.Fatalf("GetEchoMessage() = %#v, want valid hash relay for peer", got)
			}
		})
	}
}

func TestCalculateEchoHashBindsPeerBk(t *testing.T) {
	message := &Message{
		Type: Type_Peer,
		Id:   "peer",
		Body: &Message_Peer{Peer: &BodyPeer{Bk: &birkhoffinterpolation.BkParameterMessage{X: []byte("first")}}},
	}
	firstHash, err := message.CalculateEchoHash()
	if err != nil {
		t.Fatalf("CalculateEchoHash() error = %v", err)
	}

	message.GetPeer().Bk.X = []byte("second")
	secondHash, err := message.CalculateEchoHash()
	if err != nil {
		t.Fatalf("CalculateEchoHash() error = %v", err)
	}
	if bytes.Equal(firstHash, secondHash) {
		t.Fatal("CalculateEchoHash() did not bind the peer Bk")
	}
}
