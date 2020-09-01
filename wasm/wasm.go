// +build js,wasm
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
	"encoding/hex"
	"errors"
	"syscall/js"

	"github.com/getamis/alice/wasm/message"
	"github.com/golang/protobuf/proto"
)

// --- Functions exported to JS
func newDKG(this js.Value, args []js.Value) interface{} {
	if len(args) != 5 {
		return toJSError(errors.New("Invalid number of arguments"))
	}

	// Build peer manager
	sendCallback := args[3]
	selfID := args[0].String()
	var peers = make([]string, args[1].Length())
	for i := 0; i < args[1].Length(); i++ {
		peerID := args[1].Index(i).String()
		peers[i] = peerID
	}
	pm := NewPeerManager(selfID, peers, sendCallback)

	// Init service
	password := args[2].String()
	var err error
	srv, err = NewDKGService([]byte(password), pm, args[4])
	if err != nil {
		return toJSError(err)
	}

	// Start service
	srv.Start()
	return nil
}

func handleDKGData(this js.Value, args []js.Value) interface{} {
	data := args[0].String()
	dkgData := &message.Message{}
	msg, err := hex.DecodeString(data)
	if err != nil {
		srv.Stop()
		return toJSError(err)
	}
	// unmarshal it
	err = proto.Unmarshal(msg, dkgData)
	if err != nil {
		srv.Stop()
		return toJSError(err)
	}

	err = srv.AddMessage(dkgData.GetDkgData())
	if err != nil {
		srv.Stop()
		return toJSError(err)
	}
	return nil
}

func toJSError(err error) map[string]interface{} {
	return map[string]interface{}{
		"error": err.Error(),
	}
}

func main() {
	js.Global().Set("newDKG", js.FuncOf(newDKG))
	js.Global().Set("handleDKGData", js.FuncOf(handleDKGData))
	<-make(chan bool)
}
