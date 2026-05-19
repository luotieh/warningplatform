package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"vulnscan-backend/agent"
	"vulnscan-backend/agent/monitor"
	"vulnscan-backend/agent/scanner"
)

func runAgent(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "", "配置文件路径（TOML/YAML/JSON）")
	masterURL := fs.String("master-url", "", "主控服务地址")
	token := fs.String("token", "", "节点 Token / UUID")
	secret := fs.String("secret", "", "节点密钥")
	topology := fs.String("topology", "", "网络拓扑标识")
	credentialsFile := fs.String("credentials-file", "", "入网凭证 JSON 文件路径")
	maxConcurrent := fs.Int("max-concurrent", -1, "最大并发（0=自动，-1=不覆盖）")
	taskTimeout := fs.String("task-timeout", "", "单任务超时（如 10m）")
	heartbeatInterval := fs.String("heartbeat-interval", "", "心跳间隔（如 10s）")
	logLevel := fs.String("log-level", "", "日志级别：debug、info、warn、error")
	fs.Usage = func() { printRunHelp() }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	overrides := agent.RuntimeConfigOverrides{ConfigPath: *configPath}
	if *masterURL != "" {
		overrides.MasterURL = *masterURL
	}
	if *token != "" {
		overrides.Token = *token
	}
	if *secret != "" {
		overrides.Secret = *secret
	}
	if *topology != "" {
		overrides.Topology = *topology
	}
	if *credentialsFile != "" {
		overrides.CredentialsFile = *credentialsFile
	}
	if *maxConcurrent >= 0 {
		v := *maxConcurrent
		overrides.MaxConcurrent = &v
	}
	if *taskTimeout != "" {
		overrides.TaskTimeout = *taskTimeout
	}
	if *heartbeatInterval != "" {
		overrides.HeartbeatInterval = *heartbeatInterval
	}
	if *logLevel != "" {
		overrides.LogLevel = *logLevel
	}

	runtimeCfg, err := agent.LoadRuntimeConfig(overrides)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	level, err := agent.ParseLogLevel(runtimeCfg.LogLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	agent.SetupCLILogger(level, os.Stdout)

	if err := agent.EnsureRuntimeCredentials(&runtimeCfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	agentCfg, err := runtimeCfg.AgentConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	slog.Info("正在启动 Agent",
		"version", agent.Version,
		"master", agentCfg.MasterURL,
		"node_uuid", agent.MaskNodeID(agentCfg.Token),
		"credentials_file", strings.TrimSpace(runtimeCfg.CredentialsFile),
	)

	monitorExec := monitor.NewExecutor(agentCfg.MasterURL, agentCfg.Token, agentCfg.Secret)
	scannerExec := scanner.NewExecutor()
	a := agent.New(agentCfg, monitorExec, scannerExec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.Start(ctx); err != nil {
		slog.Error("Agent 启动失败", "error", err)
		return 1
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("正在关闭 Agent…")
	a.Stop()
	slog.Info("Agent 已退出")
	return 0
}
