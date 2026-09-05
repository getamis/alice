package sign

import "testing"

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
			if !ok || !echo.IsValid() || echo.GetId() != "peer" {
				t.Fatalf("GetEchoMessage() = %#v, want valid message for peer", got)
			}
		})
	}
}
