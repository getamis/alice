// Copyright © 2020 AMIS Technologies
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

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/getamis/alice/example/cggmp/dkg"
	"github.com/getamis/alice/example/cggmp/reshare"
	"github.com/getamis/alice/example/cggmp/signer"
)

var cmd = &cobra.Command{
	Use:   "tss-example",
	Short: `This is a TSS example`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	cmd.PersistentFlags().String("config", "", "config file path")

	cmd.AddCommand(dkg.Cmd)
	cmd.AddCommand(reshare.Cmd)
	cmd.AddCommand(signer.Cmd)
	cmd.AddCommand(signer.SixRoundCmd)
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
