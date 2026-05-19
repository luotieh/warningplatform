package main

import "strings"

// runFlagPrefixes 无子命令时识别为 run 的全局选项（如 vulnscan-agent -config agent.toml）。
var runFlagPrefixes = []string{
	"-config", "--config",
	"-master-url", "--master-url",
	"-token", "--token",
	"-secret", "--secret",
	"-topology", "--topology",
	"-credentials-file", "--credentials-file",
	"-max-concurrent", "--max-concurrent",
	"-task-timeout", "--task-timeout",
	"-heartbeat-interval", "--heartbeat-interval",
	"-log-level", "--log-level",
}

func isRunFlag(arg string) bool {
	if !strings.HasPrefix(arg, "-") {
		return false
	}
	for _, p := range runFlagPrefixes {
		if arg == p || strings.HasPrefix(arg, p+"=") {
			return true
		}
	}
	return false
}

// rootCommands 顶层命令一览（用于帮助与校验）。
var rootCommands = []struct {
	Names   []string
	Summary string
}{
	{[]string{"run", "start"}, "启动 Agent（连接主控，执行扫描/监测任务）"},
	{[]string{"enroll"}, "生成节点入网注册包（JSON + RSA 私钥 .key）"},
	{[]string{"decrypt-credentials", "decrypt"}, "解密主控下发的凭证信封"},
	{[]string{"config"}, "管理配置文件：init / show / validate"},
	{[]string{"version"}, "打印版本号"},
	{[]string{"help"}, "显示帮助（help <命令> 或 help config <子命令>）"},
}

// configSubcommands config 子命令一览。
var configSubcommands = []struct {
	Names   []string
	Summary string
}{
	{[]string{"init", "generate", "create"}, "生成默认 TOML 配置文件"},
	{[]string{"show", "print"}, "加载并打印有效配置（密钥脱敏）"},
	{[]string{"validate", "check"}, "校验配置能否成功加载"},
	{[]string{"help"}, "显示 config 帮助"},
}

func isKnownCommand(name string) bool {
	name = normalizeCmdName(name)
	for _, c := range rootCommands {
		for _, n := range c.Names {
			if name == n {
				return true
			}
		}
	}
	switch name {
	case "-v", "--version", "-h", "--help":
		return true
	default:
		return false
	}
}

func normalizeCmdName(name string) string {
	switch name {
	case "-v", "--version":
		return "version"
	case "-h", "--help":
		return "help"
	default:
		return name
	}
}
