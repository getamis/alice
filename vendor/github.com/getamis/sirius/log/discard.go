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

func Discard() Logger {
	return &discard{}
}

// ----------------------------------------------------------------------------

type discard struct {
}

func (l *discard) New(ctx ...interface{}) Logger {
	return l
}

func (l *discard) Trace(msg string, ctx ...interface{}) {
}

func (l *discard) Debug(msg string, ctx ...interface{}) {
}

func (l *discard) Info(msg string, ctx ...interface{}) {
}

func (l *discard) Warn(msg string, ctx ...interface{}) {
}

func (l *discard) Error(msg string, ctx ...interface{}) {
}

func (l *discard) Crit(msg string, ctx ...interface{}) {
}

func (l *discard) SetHandler(h Handler) {
}

func (l *discard) GetHandler() Handler {
	return nil
}

func (l *discard) SetSkipLevel(skip int) {
}
