package refresh

import "testing"

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
			if !ok || !echo.IsValid() || echo.GetId() != "peer" {
				t.Fatalf("GetEchoMessage() = %#v, want valid message for peer", got)
			}
		})
	}
}
