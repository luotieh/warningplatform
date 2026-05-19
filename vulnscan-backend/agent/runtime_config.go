package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/pkg/clusterconn"
)

// RuntimeConfig 为 Agent 进程级配置（TOML/YAML/JSON 文件 + 环境变量 + CLI 合并）。
type RuntimeConfig struct {
	MasterURL         string `toml:"master_url" yaml:"master_url" json:"master_url"`
	Token             string `toml:"token" yaml:"token" json:"token"`
	Secret            string `toml:"secret" yaml:"secret" json:"secret"`
	Topology          string `toml:"topology" yaml:"topology" json:"topology"`
	CredentialsFile   string `toml:"credentials_file" yaml:"credentials_file" json:"credentials_file"`
	MaxConcurrent     int    `toml:"max_concurrent" yaml:"max_concurrent" json:"max_concurrent"`
	TaskTimeout       string `toml:"task_timeout" yaml:"task_timeout" json:"task_timeout"`
	HeartbeatInterval string `toml:"heartbeat_interval" yaml:"heartbeat_interval" json:"heartbeat_interval"`
	LogLevel          string `toml:"log_level" yaml:"log_level" json:"log_level"`
}

// RuntimeConfigOverrides 由 CLI 传入的非空字段覆盖已加载配置。
type RuntimeConfigOverrides struct {
	ConfigPath        string
	MasterURL         string
	Token             string
	Secret            string
	Topology          string
	CredentialsFile   string
	MaxConcurrent     *int
	TaskTimeout       string
	HeartbeatInterval string
	LogLevel          string
}

// DefaultRuntimeConfig 返回内置默认值（不含凭证）。
func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		MasterURL:         "http://127.0.0.1:8080/api",
		MaxConcurrent:     0,
		TaskTimeout:       "10m",
		HeartbeatInterval: "10s",
		LogLevel:          "info",
	}
}

// LoadRuntimeConfig 按 默认值 → 配置文件 → 环境变量 → overrides 合并。
func LoadRuntimeConfig(overrides RuntimeConfigOverrides) (RuntimeConfig, error) {
	cfg := DefaultRuntimeConfig()

	configPath := strings.TrimSpace(overrides.ConfigPath)
	if configPath == "" {
		configPath = strings.TrimSpace(os.Getenv("AGENT_CONFIG_FILE"))
	}
	if configPath == "" {
		if p, ok := findDefaultConfigFile(); ok {
			configPath = p
		}
	}
	if configPath != "" {
		fileCfg, err := LoadRuntimeConfigFile(configPath)
		if err != nil {
			return cfg, fmt.Errorf("load config file %q: %w", configPath, err)
		}
		mergeRuntimeConfig(&cfg, &fileCfg)
	}

	applyRuntimeConfigEnv(&cfg)
	applyRuntimeConfigOverrides(&cfg, overrides)

	if err := applyCredentialsFileToRuntime(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// LoadRuntimeConfigFile 读取 TOML/YAML/JSON 配置文件（按扩展名解析）。
func LoadRuntimeConfigFile(path string) (RuntimeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RuntimeConfig{}, err
	}
	var cfg RuntimeConfig
	if err := unmarshalRuntimeConfigFile(path, b, &cfg); err != nil {
		return RuntimeConfig{}, err
	}
	return cfg, nil
}

func findDefaultConfigFile() (string, bool) {
	candidates := []string{
		DefaultConfigFileName,
		filepath.Join("config", DefaultConfigFileName),
		"agent.yaml",
		"agent.yml",
		filepath.Join("config", "agent.yaml"),
		filepath.Join("config", "agent.yml"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func mergeRuntimeConfig(dst *RuntimeConfig, src *RuntimeConfig) {
	if dst == nil || src == nil {
		return
	}
	if strings.TrimSpace(src.MasterURL) != "" {
		dst.MasterURL = strings.TrimSpace(src.MasterURL)
	}
	if strings.TrimSpace(src.Token) != "" {
		dst.Token = strings.TrimSpace(src.Token)
	}
	if strings.TrimSpace(src.Secret) != "" {
		dst.Secret = strings.TrimSpace(src.Secret)
	}
	if strings.TrimSpace(src.Topology) != "" {
		dst.Topology = strings.TrimSpace(src.Topology)
	}
	if strings.TrimSpace(src.CredentialsFile) != "" {
		dst.CredentialsFile = strings.TrimSpace(src.CredentialsFile)
	}
	if src.MaxConcurrent != 0 {
		dst.MaxConcurrent = src.MaxConcurrent
	}
	if strings.TrimSpace(src.TaskTimeout) != "" {
		dst.TaskTimeout = strings.TrimSpace(src.TaskTimeout)
	}
	if strings.TrimSpace(src.HeartbeatInterval) != "" {
		dst.HeartbeatInterval = strings.TrimSpace(src.HeartbeatInterval)
	}
	if strings.TrimSpace(src.LogLevel) != "" {
		dst.LogLevel = strings.TrimSpace(src.LogLevel)
	}
}

func applyRuntimeConfigEnv(cfg *RuntimeConfig) {
	setEnvString := func(keys []string, apply func(string)) {
		for _, k := range keys {
			if v := strings.TrimSpace(os.Getenv(k)); v != "" {
				apply(v)
				return
			}
		}
	}
	setEnvString([]string{"MASTER_URL", "AGENT_MASTER_URL"}, func(v string) { cfg.MasterURL = v })
	setEnvString([]string{"AGENT_TOKEN"}, func(v string) { cfg.Token = v })
	setEnvString([]string{"AGENT_SECRET"}, func(v string) { cfg.Secret = v })
	setEnvString([]string{"AGENT_TOPOLOGY"}, func(v string) { cfg.Topology = v })
	setEnvString([]string{"AGENT_CREDENTIALS_FILE"}, func(v string) { cfg.CredentialsFile = v })
	setEnvString([]string{"AGENT_TASK_TIMEOUT"}, func(v string) { cfg.TaskTimeout = v })
	setEnvString([]string{"AGENT_HEARTBEAT_INTERVAL"}, func(v string) { cfg.HeartbeatInterval = v })
	setEnvString([]string{"AGENT_LOG_LEVEL", "LOG_LEVEL"}, func(v string) { cfg.LogLevel = v })

	if v := strings.TrimSpace(os.Getenv("MAX_CONCURRENT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxConcurrent = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("AGENT_MAX_CONCURRENT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxConcurrent = n
		}
	}
}

func applyRuntimeConfigOverrides(cfg *RuntimeConfig, o RuntimeConfigOverrides) {
	if strings.TrimSpace(o.MasterURL) != "" {
		cfg.MasterURL = strings.TrimSpace(o.MasterURL)
	}
	if strings.TrimSpace(o.Token) != "" {
		cfg.Token = strings.TrimSpace(o.Token)
	}
	if strings.TrimSpace(o.Secret) != "" {
		cfg.Secret = strings.TrimSpace(o.Secret)
	}
	if strings.TrimSpace(o.Topology) != "" {
		cfg.Topology = strings.TrimSpace(o.Topology)
	}
	if strings.TrimSpace(o.CredentialsFile) != "" {
		cfg.CredentialsFile = strings.TrimSpace(o.CredentialsFile)
	}
	if o.MaxConcurrent != nil && *o.MaxConcurrent >= 0 {
		cfg.MaxConcurrent = *o.MaxConcurrent
	}
	if strings.TrimSpace(o.TaskTimeout) != "" {
		cfg.TaskTimeout = strings.TrimSpace(o.TaskTimeout)
	}
	if strings.TrimSpace(o.HeartbeatInterval) != "" {
		cfg.HeartbeatInterval = strings.TrimSpace(o.HeartbeatInterval)
	}
	if strings.TrimSpace(o.LogLevel) != "" {
		cfg.LogLevel = strings.TrimSpace(o.LogLevel)
	}
}

func applyCredentialsFileToRuntime(cfg *RuntimeConfig) error {
	path := strings.TrimSpace(cfg.CredentialsFile)
	if path == "" {
		return nil
	}
	cred, err := LoadCredentialsFile(path)
	if err != nil {
		return fmt.Errorf("credentials file %q: %w", path, err)
	}
	if cred.MasterURL != "" {
		if err := clusterconn.ValidateMasterURL(cred.MasterURL); err != nil {
			if errCfg := clusterconn.ValidateMasterURL(cfg.MasterURL); errCfg == nil {
				// 凭据里可能误写为 "/api"，保留 agent.toml / 环境变量中的完整地址
			} else {
				return fmt.Errorf("凭据文件 master_url 无效: %w（请在 agent.toml 设置 master_url=http://主机:端口/api 或重新签发）", err)
			}
		} else {
			cfg.MasterURL = cred.MasterURL
		}
	}
	cfg.Token = cred.NodeUUID
	cfg.Secret = cred.Secret
	if cred.Topology != "" {
		cfg.Topology = cred.Topology
	}
	return nil
}

// AgentConfig 将运行时配置转为 agent.Config。
func (r RuntimeConfig) AgentConfig() (Config, error) {
	masterURL := trimMasterURL(r.MasterURL)
	if err := clusterconn.ValidateMasterURL(masterURL); err != nil {
		return Config{}, fmt.Errorf("master_url: %w", err)
	}
	cfg := Config{
		MasterURL:     masterURL,
		Token:         strings.TrimSpace(r.Token),
		Secret:        strings.TrimSpace(r.Secret),
		Topology:      strings.TrimSpace(r.Topology),
		MaxConcurrent: r.MaxConcurrent,
	}
	if d, err := parseDurationOrDefault(r.TaskTimeout, 10*time.Minute); err != nil {
		return cfg, fmt.Errorf("task_timeout: %w", err)
	} else {
		cfg.TaskTimeout = d
	}
	if d, err := parseDurationOrDefault(r.HeartbeatInterval, 10*time.Second); err != nil {
		return cfg, fmt.Errorf("heartbeat_interval: %w", err)
	} else {
		cfg.HeartbeatInterval = d
	}
	cfg.defaults()
	return cfg, nil
}

// RedactedCopy 返回用于打印的副本（隐藏 secret）。
func (r RuntimeConfig) RedactedCopy() RuntimeConfig {
	out := r
	if out.Secret != "" {
		out.Secret = "***"
	}
	return out
}

func parseDurationOrDefault(raw string, fallback time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	return time.ParseDuration(raw)
}

// ParseLogLevel 解析 slog 日志级别。
func ParseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("未知日志级别 %q（可选：debug、info、warn、error）", raw)
	}
}

func unmarshalJSONRuntimeConfig(b []byte, cfg *RuntimeConfig) error {
	return json.Unmarshal(b, cfg)
}
