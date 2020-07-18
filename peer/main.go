/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/hyperledger/fabric/peer/chaincode"
	"github.com/hyperledger/fabric/peer/channel"
	"github.com/hyperledger/fabric/peer/clilogging"
	"github.com/hyperledger/fabric/peer/common"
	"github.com/hyperledger/fabric/peer/node"
	"github.com/hyperledger/fabric/peer/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// The main command describes the service and
// defaults to printing the help message.
var mainCmd = &cobra.Command{
	Use: "peer"} // 在这里设置主命令为 “peer”

func main() {

	// For environment variables.
	viper.SetEnvPrefix(common.CmdRoot) // 根據 core.yaml 設置环境变量
	viper.AutomaticEnv()               //会获取所有的环境变量，同时如果过设置了前缀则会自动补全前缀名
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer) //替换 key 中的某些字符，来转化为对应的环境变量

	// Define command-line flags that are valid for all peer commands and
	// subcommands.
	mainFlags := mainCmd.PersistentFlags() //设置全局属性对象

	mainFlags.String("logging-level", "", "Legacy logging level flag")  //设置新的命令 logging-level
	viper.BindPFlag("logging_level", mainFlags.Lookup("logging-level")) // 将命令 logging-level 绑定到命令 logging_level 上
	mainFlags.MarkHidden("logging-level")                               // 隐藏命令 logging-level 在 help 和 usage 中的说明

	mainCmd.AddCommand(version.Cmd())
	mainCmd.AddCommand(node.Cmd())
	mainCmd.AddCommand(chaincode.Cmd(nil))
	mainCmd.AddCommand(clilogging.Cmd(nil))
	mainCmd.AddCommand(channel.Cmd(nil))

	// On failure Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if mainCmd.Execute() != nil { // 初始化 Cobra
		os.Exit(1)
	}
}
