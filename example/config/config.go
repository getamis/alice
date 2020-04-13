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
package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Pubkey struct {
	X string `yaml:"x"`
	Y string `yaml:"y"`
}

type BK struct {
	X    string `yaml:"x"`
	Rank uint32 `yaml:"rank"`
}

type DKGResult struct {
	Share  string        `yaml:"share"`
	Pubkey Pubkey        `yaml:"pubkey"`
	BKs    map[string]BK `yaml:"bks"`
}

type SignerResult struct {
	R string `yaml:"r"`
	S string `yaml:"s"`
}

type Config struct {
	Port      int64   `yaml:"port"`
	Rank      uint32  `yaml:"rank"`
	Threshold uint32  `yaml:"threshold"`
	Peers     []int64 `yaml:"peers"`
}

func ReadConfigFile(filaPath string) (*Config, error) {
	c := &Config{}
	yamlFile, err := ioutil.ReadFile(filaPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func ReadDKGResultFile(filaPath string) (*DKGResult, error) {
	r := &DKGResult{}
	yamlFile, err := ioutil.ReadFile(filaPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func WriteYamlFile(yamlData interface{}, filePath string) error {
	data, err := yaml.Marshal(yamlData)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}
