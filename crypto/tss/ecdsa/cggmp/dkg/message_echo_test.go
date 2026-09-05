package dkg

import "testing"

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
			if !ok || !echo.IsValid() || echo.GetId() != "peer" {
				t.Fatalf("GetEchoMessage() = %#v, want valid message for peer", got)
			}
		})
	}
}
