package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"vulnscan-backend/agent"
)

func runConfigCommand(args []string) int {
	if len(args) == 0 {
		printConfigHelp()
		return 2
	}

	// config -h / config --help
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		printConfigHelp()
		return 0
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "init", "generate", "create":
		return runConfigInit(rest)
	case "show", "print":
		return runConfigShow(rest)
	case "validate", "check":
		return runConfigValidate(rest)
	case "help", "-h", "--help":
		if len(rest) > 0 {
			printHelpForConfigSub(rest[0])
		} else {
			printConfigHelp()
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "未知的 config 子命令: %q\n\n", sub)
		printConfigHelp()
		return 2
	}
}

func runConfigInit(args []string) int {
	fs := flag.NewFlagSet("config init", flag.ExitOnError)
	out := fs.String("out", agent.DefaultConfigFileName, "输出的 TOML 配置文件路径")
	force := fs.Bool("force", false, "覆盖已存在的文件")
	fs.Usage = func() { printConfigInitHelp() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := agent.WriteRuntimeConfigTemplate(*out, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "已生成配置文件: %s\n请按需修改后执行: %s run -config %s\n", *out, cliName, *out)
	return 0
}

func runConfigShow(args []string) int {
	fs := flag.NewFlagSet("config show", flag.ExitOnError)
	configPath := fs.String("config", "", "配置文件路径")
	format := fs.String("format", "toml", "输出格式：toml 或 json")
	fs.Usage = func() { printConfigShowHelp() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := agent.LoadRuntimeConfig(agent.RuntimeConfigOverrides{ConfigPath: *configPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	redacted := cfg.RedactedCopy()
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(redacted); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "toml", "":
		b, err := toml.Marshal(redacted)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(string(b))
	default:
		fmt.Fprintf(os.Stderr, "不支持的格式 %q（请使用 toml 或 json）\n", *format)
		return 2
	}
	return 0
}

func runConfigValidate(args []string) int {
	fs := flag.NewFlagSet("config validate", flag.ExitOnError)
	configPath := fs.String("config", "", "配置文件路径")
	fs.Usage = func() { printConfigValidateHelp() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := agent.LoadRuntimeConfig(agent.RuntimeConfigOverrides{ConfigPath: *configPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置无效:", err)
		return 1
	}
	if _, err := cfg.AgentConfig(); err != nil {
		fmt.Fprintln(os.Stderr, "配置无效:", err)
		return 1
	}
	if cfg.Token == "" && strings.TrimSpace(cfg.CredentialsFile) == "" {
		fmt.Fprintln(os.Stderr, "提示: 未配置 token 且未设置 credentials_file，运行时将使用临时标识 agent-<主机名>-<进程号>")
	}
	fmt.Fprintln(os.Stderr, "配置校验通过")
	return 0
}
