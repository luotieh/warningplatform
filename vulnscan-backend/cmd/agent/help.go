package main

import (
	"fmt"
	"os"
)

const cliName = "vulnscan-agent"

func printRootHelp() {
	fmt.Fprintf(os.Stdout, `%s — 统一扫描/监测节点 Agent（版本 %s）

用法:
  %s <命令> [子命令] [选项]
  %s [run 选项]              # 省略 run 时，直接写选项等价于 run

命令列表:
  run, start                 启动 Agent
  enroll                     生成节点入网注册包
  decrypt-credentials, decrypt
                             解密主控下发的凭证信封
  config init|show|validate  管理 TOML 配置文件
  version, -v, --version     打印版本号
  help [命令]                显示帮助
  help config <子命令>       显示 config 子命令帮助

配置加载顺序（后者覆盖前者）:
  1. 内置默认值
  2. 配置文件（-config / AGENT_CONFIG_FILE / ./agent.toml / ./config/agent.toml，兼容 .yaml/.json）
  3. 环境变量
  4. 命令行参数
  5. credentials_file 入网凭证（覆盖 token、secret、master_url、topology）

环境变量:
  AGENT_CONFIG_FILE         配置文件路径
  MASTER_URL, AGENT_MASTER_URL
                            主控 API 根地址（须含 /api，如 http://127.0.0.1:8080/api）
  AGENT_TOKEN               节点 UUID
  AGENT_SECRET              节点密钥
  AGENT_TOPOLOGY            网络拓扑（master_public_node_private | master_private_node_public）
  AGENT_CREDENTIALS_FILE    入网凭证 JSON 路径
  MAX_CONCURRENT, AGENT_MAX_CONCURRENT
                            最大并发（0=按本机资源自动）
  AGENT_TASK_TIMEOUT        任务超时（如 10m）
  AGENT_HEARTBEAT_INTERVAL  心跳间隔（如 10s）
  AGENT_LOG_LEVEL           日志级别：debug | info | warn | error

典型入网流程:
  %s config init -out agent.toml
  %s enroll -out node-enrollment.json
  # 将 node-enrollment.json 上传主控，保留 node-enrollment.key 在本机
  %s decrypt-credentials -envelope <主控信封.json> -key node-enrollment.key
  # 编辑 agent.toml：credentials_file = "./node-agent.credentials.json"
  %s run -config agent.toml

常用命令速查:
  %s config init [-out agent.toml] [-force]
  %s config validate [-config agent.toml]
  %s config show [-config agent.toml] [-format toml|json]
  %s run -config agent.toml
  %s run -master-url http://127.0.0.1:8080/api -credentials-file ./node-agent.credentials.json
  %s enroll [-out node-enrollment.json]
  %s decrypt-credentials -envelope <file> -key <file.key> [-out node-agent.credentials.json]

详细说明: %s help <命令>  或  %s help config <子命令>

`,
		cliName, agentVersion(), cliName, cliName,
		cliName, cliName, cliName, cliName,
		cliName, cliName, cliName, cliName, cliName, cliName, cliName,
		cliName, cliName,
	)
}

func printRunHelp() {
	fmt.Fprintf(os.Stdout, `用法:
  %s run [选项]
  %s [选项]                    # 省略 run

说明:
  启动 Agent，连接主控 /api/node-api，拉取并执行扫描、监测任务。

选项:
  -config string
        配置文件路径（TOML / YAML / JSON）
  -master-url string
        主控 API 根地址（须含 /api，如 http://127.0.0.1:8080/api）
  -token string
        节点 UUID（入网后由主控分配）
  -secret string
        节点密钥
  -topology string
        网络拓扑：master_public_node_private 或 master_private_node_public
  -credentials-file string
        入网凭证 JSON（decrypt-credentials 的输出，推荐）
  -max-concurrent int
        最大并发任务数（0=自动，-1=不覆盖已有配置）
  -task-timeout duration
        单任务超时（如 10m、30s）
  -heartbeat-interval duration
        心跳间隔（如 10s）
  -log-level string
        日志级别：debug | info | warn | error
  -h, --help
        显示本帮助

示例:
  %s config init -out agent.toml
  %s run -config ./agent.toml
  %s -config ./agent.toml
  %s run -credentials-file ./node-agent.credentials.json

`,
		cliName, cliName, cliName, cliName, cliName, cliName,
	)
}

func printEnrollHelp() {
	fmt.Fprintf(os.Stdout, `用法:
  %s enroll [选项]

说明:
  生成本机节点入网材料：
  - <out>          注册 JSON（上传主控）
  - <out>.key      RSA 私钥（仅保留本机，勿上传）

选项:
  -out string
        注册 JSON 输出路径（默认 node-enrollment.json）
  -h, --help
        显示本帮助

示例:
  %s enroll
  %s enroll -out ./node-enrollment.json

下一步:
  上传 JSON 至主控完成审批/入网后，使用主控下发的信封执行 decrypt-credentials。

`,
		cliName, cliName, cliName,
	)
}

func printDecryptHelp() {
	fmt.Fprintf(os.Stdout, `用法:
  %s decrypt-credentials [选项]
  %s decrypt [选项]             # 同上（别名）

说明:
  使用 enroll 生成的 .key 私钥，解密主控下发的加密凭证信封。

选项:
  -envelope string
        主控下发的加密信封 JSON（必填）
  -key string
        enroll 生成的 RSA 私钥路径（必填，通常为 *.key）
  -out string
        明文凭证输出路径（默认 node-agent.credentials.json）
  -h, --help
        显示本帮助

示例:
  %s decrypt-credentials -envelope cred-envelope.json -key node-enrollment.key
  %s decrypt -envelope cred-envelope.json -key node-enrollment.key -out ./node-agent.credentials.json

下一步:
  在 agent.toml 中设置 credentials_file，或设置环境变量 AGENT_CREDENTIALS_FILE，然后:
  %s run -config agent.toml

`,
		cliName, cliName, cliName, cliName, cliName,
	)
}

func printConfigHelp() {
	fmt.Fprintf(os.Stdout, `用法:
  %s config <子命令> [选项]

说明:
  管理 Agent 配置，推荐使用 TOML（agent.toml）。

子命令:
  init, generate, create
        生成带注释的默认 TOML 配置文件
  show, print
        加载并打印合并后的有效配置（secret 脱敏为 ***）
  validate, check
        校验配置格式与必填项（不启动 Agent）
  help
        显示本帮助

示例:
  %s config init -out agent.toml
  %s config init -out ./config/agent.toml -force
  %s config validate -config agent.toml
  %s config show -config agent.toml -format toml

子命令帮助:
  %s help config init
  %s help config show
  %s help config validate

`,
		cliName, cliName, cliName, cliName, cliName, cliName, cliName, cliName,
	)
}

func printConfigInitHelp() {
	fmt.Fprintf(os.Stdout, `用法:
  %s config init [选项]
  %s config generate [选项]     # 别名
  %s config create [选项]       # 别名

说明:
  生成默认 TOML 配置文件，包含 master_url、超时、日志级别等及中文注释。

选项:
  -out string
        输出路径（默认 agent.toml）
  -force
        覆盖已存在的文件
  -h, --help
        显示本帮助

示例:
  %s config init
  %s config init -out ./config/agent.toml
  %s config init -out agent.toml -force

`,
		cliName, cliName, cliName, cliName, cliName, cliName,
	)
}

func printConfigShowHelp() {
	fmt.Fprintf(os.Stdout, `用法:
  %s config show [选项]
  %s config print [选项]         # 别名

说明:
  按与 run 相同的规则加载配置（文件 → 环境变量），打印合并结果。

选项:
  -config string
        配置文件路径；省略则自动查找 agent.toml 等
  -format string
        输出格式：toml（默认）或 json
  -h, --help
        显示本帮助

示例:
  %s config show
  %s config show -config ./agent.toml
  %s config show -config ./agent.toml -format json

`,
		cliName, cliName, cliName, cliName, cliName,
	)
}

func printConfigValidateHelp() {
	fmt.Fprintf(os.Stdout, `用法:
  %s config validate [选项]
  %s config check [选项]        # 别名

说明:
  校验配置文件能否解析，以及 task_timeout、heartbeat 等字段是否合法。

选项:
  -config string
        配置文件路径；省略则自动查找
  -h, --help
        显示本帮助

示例:
  %s config validate
  %s config validate -config ./agent.toml

`,
		cliName, cliName, cliName, cliName,
	)
}

func printHelpForConfigSub(sub string) {
	switch sub {
	case "init", "generate", "create":
		printConfigInitHelp()
	case "show", "print":
		printConfigShowHelp()
	case "validate", "check":
		printConfigValidateHelp()
	case "help", "-h", "--help":
		printConfigHelp()
	default:
		fmt.Fprintf(os.Stderr, "未知的 config 子命令: %q\n\n", sub)
		printConfigHelp()
	}
}

func printHelpForCommand(cmd string) {
	switch normalizeCmdName(cmd) {
	case "help":
		printRootHelp()
	case "run", "start":
		printRunHelp()
	case "enroll":
		printEnrollHelp()
	case "decrypt-credentials", "decrypt":
		printDecryptHelp()
	case "config":
		printConfigHelp()
	case "version":
		fmt.Printf("%s %s\n", cliName, agentVersion())
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %q\n\n", cmd)
		printRootHelp()
		os.Exit(2)
	}
}
