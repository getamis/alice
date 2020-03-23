// Copyright 2017 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"fmt"
	"path"
	"path/filepath"
	"sync/atomic"

	"github.com/rollbar/rollbar-go"
)

// RollbarHandler enables send the logs to rollbar
type RollbarHandler struct {
	SkipLevel int
}

func (h *RollbarHandler) Log(r *Record) error {
	var lv string
	switch r.Lvl {
	case LvlCrit:
		lv = rollbar.CRIT
	case LvlError:
		lv = rollbar.ERR
	case LvlWarn:
		lv = rollbar.WARN
	case LvlInfo:
		lv = rollbar.INFO
	case LvlDebug:
		lv = rollbar.DEBUG
	default:
		lv = r.Lvl.AlignedString()
	}

	// Append skip level
	var interfaces []interface{}
	if h.SkipLevel != 0 {
		interfaces = append(interfaces, h.SkipLevel)
	}

	// Add timestamp
	metaData := make(map[string]interface{})
	metaData["timestamp"] = r.Time.Format(termTimeFormat)

	// Append location
	if atomic.LoadUint32(&locationEnabled) != 0 {
		// Log origin printing was requested, format the location path and line number
		location := fmt.Sprintf("%+v", r.Call)
		location = path.Join(filepath.Base(filepath.Dir(location)), filepath.Base(location))

		metaData["location"] = location
	}

	interfaces = append(interfaces, r.Msg)
	ctx := r.Ctx
	for i := 0; i < len(ctx); i += 2 {
		k, ok := ctx[i].(string)
		v := formatLogfmtValue(ctx[i+1], false)
		if !ok {
			k, v = errorKey, formatLogfmtValue(k, false)
		}

		if ctx[i+1] != nil {
			// Append error
			err, ok := ctx[i+1].(error)
			if ok {
				interfaces = append(interfaces, err)
				// Append message to metadata
				metaData["msg"] = r.Msg
			} else {
				metaData[k] = v
			}
		}
	}
	interfaces = append(interfaces, metaData)
	rollbar.Log(lv, interfaces...)
	return nil
}
