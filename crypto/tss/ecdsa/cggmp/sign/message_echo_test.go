package sign

import (
	"bytes"
	"testing"
)

func TestGetEchoMessage(t *testing.T) {
	tests := []struct {
		name     string
		msgType  Type
		wantEcho bool
	}{
		{name: "round 1 common ciphertexts", msgType: Type_Round1, wantEcho: true},
		{name: "round 2 common gamma", msgType: Type_Round2, wantEcho: true},
		{name: "round 3 common delta", msgType: Type_Round3, wantEcho: true},
		{name: "round 4", msgType: Type_Round4, wantEcho: true},
		{name: "error 1", msgType: Type_Err1, wantEcho: false},
		{name: "error 2", msgType: Type_Err2, wantEcho: false},
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

func TestCalculateEchoHashBindsRound1Ciphertext(t *testing.T) {
	message := &Message{
		Type: Type_Round1,
		Id:   "peer",
		Body: &Message_Round1{Round1: &Round1Msg{KCiphertext: []byte("first")}},
	}
	firstHash, err := message.CalculateEchoHash()
	if err != nil {
		t.Fatalf("CalculateEchoHash() error = %v", err)
	}

	message.GetRound1().KCiphertext = []byte("second")
	secondHash, err := message.CalculateEchoHash()
	if err != nil {
		t.Fatalf("CalculateEchoHash() error = %v", err)
	}
	if bytes.Equal(firstHash, secondHash) {
		t.Fatal("CalculateEchoHash() did not bind the round 1 ciphertext")
	}
}
