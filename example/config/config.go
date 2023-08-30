// Copyright © 2023 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

type Pubkey struct {
	X string `yaml:"x"`
	Y string `yaml:"y"`
}

type ECPoint struct {
	X string `yaml:"x"`
	Y string `yaml:"y"`
}

type PaillierKey struct {
	P string `yaml:"p"`
	Q string `yaml:"q"`
}

type PederssenOpenParameter struct {
	N string `yaml:"n"`
	S string `yaml:"s"`
	T string `yaml:"t"`
}

type BK struct {
	X    string `yaml:"x"`
	Rank uint32 `yaml:"rank"`
}
