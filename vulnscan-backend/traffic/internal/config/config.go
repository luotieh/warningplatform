package config

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Addr                    string
	StoreBackend            string
	DatabaseURL             string
	AutoMigrate             bool
	DBWaitSeconds           int
	InternalAPIKey          string
	FlowShadowBaseURL       string
	FlowShadowAPIKey        string
	DeepSOCBaseURL          string
	DeepSOCUsername         string
	DeepSOCPassword         string
	DeepSOCAPIKey           string
	CircularBaseURL         string
	LLMBaseURL              string
	LLMAPIKey               string
	LLMModel                string
	LLMTimeout              time.Duration
	SyncBatchSize           int
	SyncLookbackSeconds     int
	SyncMaxRetries          int
	HTTPTimeout             time.Duration
	MQBackend               string
	RabbitMQURL             string
	RabbitMQExchange        string
	RabbitMQEventQueue      string
	RabbitMQConsumerEnabled bool
	// EvidenceNodes 证据节点映射：device_id → 节点证据服务 base_url，
	// 例如 {"node-arm-offline-001": "http://127.0.0.1:25640"}。
	EvidenceNodes map[string]string
}

type LLMSettings struct {
	BaseURL          string `json:"base_url"`
	APIKey           string `json:"-"`
	APIKeyConfigured bool   `json:"api_key_configured"`
	APIKeyMasked     string `json:"api_key_masked,omitempty"`
	Model            string `json:"model"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	ConfigPath       string `json:"config_path,omitempty"`
}

// StoreSettings 流量存储配置（配置页读写与健康测试使用）。
type StoreSettings struct {
	StoreBackend       string `json:"store_backend"` // mysql / memory
	Host               string `json:"host"`
	Port               int    `json:"port"`
	User               string `json:"user"`
	Password           string `json:"-"`
	PasswordConfigured bool   `json:"password_configured"`
	PasswordMasked     string `json:"password_masked,omitempty"`
	DBName             string `json:"db_name"`
	AutoMigrate        bool   `json:"auto_migrate"`
	DBWaitSeconds      int    `json:"db_wait_seconds"`
	ConfigPath         string `json:"config_path,omitempty"`
}

// StoreTestResult 存储健康测试结果。
type StoreTestResult struct {
	OK         bool     `json:"ok"`
	Backend    string   `json:"backend"`
	LatencyMS  int64    `json:"latency_ms"`
	Tables     []string `json:"tables"`
	Error      string   `json:"error,omitempty"`
	ConfigPath string   `json:"config_path,omitempty"`
}

func Load() Config {
	cfg := Config{
		Addr:                    get("APP_ADDR", ":9010"),
		StoreBackend:            strings.ToLower(get("STORE_BACKEND", "mysql")),
		DatabaseURL:             get("DATABASE_URL", ""),
		AutoMigrate:             getBool("AUTO_MIGRATE", true),
		DBWaitSeconds:           getInt("DB_WAIT_SECONDS", 30),
		InternalAPIKey:          get("INTERNAL_API_KEY", "change-me-internal-key"),
		FlowShadowBaseURL:       get("FLOWSHADOW_BASE_URL", ""),
		FlowShadowAPIKey:        get("FLOWSHADOW_API_KEY", ""),
		DeepSOCBaseURL:          get("DEEPSOC_BASE_URL", ""),
		DeepSOCUsername:         get("DEEPSOC_USERNAME", "admin"),
		DeepSOCPassword:         get("DEEPSOC_PASSWORD", "admin"),
		DeepSOCAPIKey:           get("DEEPSOC_API_KEY", ""),
		CircularBaseURL:         get("CIRCULAR_BASE_URL", ""),
		LLMBaseURL:              get("LLM_BASE_URL", ""),
		LLMAPIKey:               get("LLM_API_KEY", ""),
		LLMModel:                get("LLM_MODEL", "deepseek-chat"),
		LLMTimeout:              time.Duration(getInt("LLM_TIMEOUT_SECONDS", 60)) * time.Second,
		SyncBatchSize:           getInt("SYNC_BATCH_SIZE", 200),
		SyncLookbackSeconds:     getInt("SYNC_LOOKBACK_SECONDS", 600),
		SyncMaxRetries:          getInt("SYNC_MAX_RETRIES", 5),
		HTTPTimeout:             time.Duration(getInt("HTTP_TIMEOUT_SECONDS", 15)) * time.Second,
		MQBackend:               strings.ToLower(get("MQ_BACKEND", "none")),
		RabbitMQURL:             get("RABBITMQ_URL", "amqp://traffic:traffic@127.0.0.1:5672/"),
		RabbitMQExchange:        get("RABBITMQ_EXCHANGE", "traffic.events"),
		RabbitMQEventQueue:      get("RABBITMQ_EVENT_QUEUE", "traffic.events.default"),
		RabbitMQConsumerEnabled: getBool("RABBITMQ_CONSUMER_ENABLED", true),
	}
	applyTrafficFileConfig(&cfg)
	return cfg
}

func SettingsFromConfig(cfg Config) LLMSettings {
	timeoutSeconds := int(cfg.LLMTimeout.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}
	return LLMSettings{
		BaseURL:          strings.TrimSpace(cfg.LLMBaseURL),
		APIKey:           strings.TrimSpace(cfg.LLMAPIKey),
		APIKeyConfigured: strings.TrimSpace(cfg.LLMAPIKey) != "",
		APIKeyMasked:     maskSecret(cfg.LLMAPIKey),
		Model:            firstNonEmpty(strings.TrimSpace(cfg.LLMModel), "deepseek-chat"),
		TimeoutSeconds:   timeoutSeconds,
		ConfigPath:       findConfigFile(),
	}
}

func SettingsFromStoreConfig(cfg Config) StoreSettings {
	s := StoreSettings{
		StoreBackend:  strings.ToLower(strings.TrimSpace(cfg.StoreBackend)),
		AutoMigrate:   cfg.AutoMigrate,
		DBWaitSeconds: normalizeDBWait(cfg.DBWaitSeconds),
		ConfigPath:    findConfigFile(),
	}
	host, port, user, dbname, passwd := parseStoreDSN(cfg.DatabaseURL)
	s.Host = host
	s.Port = port
	s.User = user
	s.DBName = dbname
	s.Password = passwd
	s.PasswordConfigured = strings.TrimSpace(passwd) != ""
	s.PasswordMasked = maskSecret(passwd)
	return s
}

func WriteTrafficLLMSettings(settings LLMSettings, updateAPIKey bool) (LLMSettings, error) {
	path := findConfigFile()
	if path == "" {
		wd, err := os.Getwd()
		if err != nil {
			return LLMSettings{}, err
		}
		path = filepath.Join(wd, "config.toml")
	}

	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return LLMSettings{}, err
	}
	content := string(raw)
	replacements := map[string]string{
		"llm_base_url":        quoteTOMLString(strings.TrimSpace(settings.BaseURL)),
		"llm_model":           quoteTOMLString(firstNonEmpty(strings.TrimSpace(settings.Model), "deepseek-chat")),
		"llm_timeout_seconds": strconv.Itoa(normalizeTimeout(settings.TimeoutSeconds)),
	}
	if updateAPIKey {
		replacements["llm_api_key"] = quoteTOMLString(strings.TrimSpace(settings.APIKey))
	}

	next := upsertTOMLSectionValues(content, "traffic", replacements, []string{"llm_base_url", "llm_api_key", "llm_model", "llm_timeout_seconds"})
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		return LLMSettings{}, friendlyConfigWriteError(path, err)
	}
	out := settings
	out.Model = firstNonEmpty(strings.TrimSpace(out.Model), "deepseek-chat")
	out.TimeoutSeconds = normalizeTimeout(out.TimeoutSeconds)
	out.ConfigPath = path
	out.APIKeyConfigured = strings.TrimSpace(out.APIKey) != ""
	out.APIKeyMasked = maskSecret(out.APIKey)
	return out, nil
}

// WriteTrafficStoreSettings 把 MySQL 存储配置写入 config.toml [traffic] 段。
// updatePassword=false 时保留原 DSN 中的密码（前端留空表示不修改）。
func WriteTrafficStoreSettings(settings StoreSettings, updatePassword bool) (StoreSettings, error) {
	path := findConfigFile()
	if path == "" {
		wd, err := os.Getwd()
		if err != nil {
			return StoreSettings{}, err
		}
		path = filepath.Join(wd, "config.toml")
	}

	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return StoreSettings{}, err
	}
	content := string(raw)

	current := SettingsFromStoreConfig(Config{StoreBackend: "mysql", DatabaseURL: extractStoreDatabaseURL(content), AutoMigrate: settings.AutoMigrate, DBWaitSeconds: settings.DBWaitSeconds})
	password := strings.TrimSpace(settings.Password)
	if !updatePassword || password == "" {
		password = current.Password
	}
	dsn := BuildStoreDSN(StoreSettings{
		Host:        strings.TrimSpace(settings.Host),
		Port:        settings.Port,
		User:        strings.TrimSpace(settings.User),
		Password:    password,
		DBName:      strings.TrimSpace(settings.DBName),
		AutoMigrate: settings.AutoMigrate,
	})
	if dsn == "" {
		return StoreSettings{}, fmt.Errorf("MySQL 配置不完整：host/user/db_name 必填")
	}

	backend := strings.ToLower(strings.TrimSpace(settings.StoreBackend))
	if backend == "" {
		backend = "mysql"
	}
	replacements := map[string]string{
		"store_backend":   quoteTOMLString(backend),
		"database_url":    quoteTOMLString(dsn),
		"auto_migrate":    strconv.FormatBool(settings.AutoMigrate),
		"db_wait_seconds": strconv.Itoa(normalizeDBWait(settings.DBWaitSeconds)),
	}
	next := upsertTOMLSectionValues(content, "traffic", replacements, []string{"store_backend", "database_url", "auto_migrate", "db_wait_seconds"})
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		return StoreSettings{}, friendlyConfigWriteError(path, err)
	}

	out := settings
	out.StoreBackend = backend
	out.Password = password
	out.PasswordConfigured = password != ""
	out.PasswordMasked = maskSecret(password)
	out.ConfigPath = path
	return out, nil
}

// friendlyConfigWriteError 把配置文件不可写（只读挂载/权限不足）转换为
// 可直接指导运维的中文错误，其余错误原样返回。
func friendlyConfigWriteError(path string, err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "read-only file system") || strings.Contains(lower, "permission denied") {
		return fmt.Errorf("配置文件不可写（%s）：请将容器配置挂载改为可写（去掉 :ro）后重试: %w", path, err)
	}
	return err
}

// TestStoreSettings 测试 MySQL 连通性并检查核心表是否已建。
func TestStoreSettings(settings StoreSettings) StoreTestResult {
	result := StoreTestResult{Backend: "mysql", Tables: []string{}, ConfigPath: findConfigFile()}
	dsn := BuildStoreDSN(settings)
	if dsn == "" {
		result.Error = "MySQL 配置不完整：host/user/db_name 必填"
		return result
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer db.Close()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		result.Error = fmt.Sprintf("连接失败: %v", err)
		return result
	}
	result.LatencyMS = time.Since(start).Milliseconds()
	rows, err := db.QueryContext(ctx, `
SELECT TABLE_NAME FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME IN ('events', 'summaries', 'event_maps', 'traffic_assets', 'asset_report_summaries')
ORDER BY TABLE_NAME`)
	if err != nil {
		result.Error = fmt.Sprintf("查询表结构失败: %v", err)
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			result.Tables = append(result.Tables, name)
		}
	}
	result.OK = true
	return result
}

// BuildStoreDSN 由结构化字段构造 go-sql-driver DSN。
func BuildStoreDSN(settings StoreSettings) string {
	host := strings.TrimSpace(settings.Host)
	user := strings.TrimSpace(settings.User)
	dbname := strings.TrimSpace(settings.DBName)
	if host == "" || user == "" || dbname == "" {
		return ""
	}
	port := settings.Port
	if port <= 0 {
		port = 3306
	}
	c := mysql.NewConfig()
	c.User = user
	c.Passwd = settings.Password
	c.Net = "tcp"
	c.Addr = fmt.Sprintf("%s:%d", host, port)
	c.DBName = dbname
	c.ParseTime = true
	c.Params = map[string]string{"charset": "utf8mb4", "loc": "UTC"}
	return c.FormatDSN()
}

func parseStoreDSN(dsn string) (host string, port int, user string, dbname string, passwd string) {
	host, port, user, dbname = "127.0.0.1", 3306, "", ""
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return
	}
	addr := cfg.Addr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		host = addr[:idx]
		if p, err := strconv.Atoi(addr[idx+1:]); err == nil {
			port = p
		}
	} else if addr != "" {
		host = addr
	}
	return host, port, cfg.User, cfg.DBName, cfg.Passwd
}

// extractStoreDatabaseURL 从 config.toml 原文提取 database_url，供写回时保留旧密码。
func extractStoreDatabaseURL(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "database_url") && strings.Contains(trimmed, "=") {
			value := strings.Trim(strings.TrimSpace(trimmed[strings.Index(trimmed, "=")+1:]), `"'`)
			if value != "" {
				return value
			}
		}
	}
	return ""
}

func applyTrafficFileConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	path := findConfigFile()
	if path == "" {
		return
	}

	var fileCfg struct {
		Traffic struct {
			StoreBackend      string `toml:"store_backend"`
			DatabaseURL       string `toml:"database_url"`
			AutoMigrate       *bool  `toml:"auto_migrate"`
			DBWaitSeconds     int    `toml:"db_wait_seconds"`
			LLMBaseURL        string `toml:"llm_base_url"`
			LLMAPIKey         string `toml:"llm_api_key"`
			LLMModel          string `toml:"llm_model"`
			LLMTimeoutSeconds int    `toml:"llm_timeout_seconds"`
		} `toml:"traffic"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if err := toml.Unmarshal(raw, &fileCfg); err != nil {
		return
	}

	if os.Getenv("STORE_BACKEND") == "" && strings.TrimSpace(fileCfg.Traffic.StoreBackend) != "" {
		cfg.StoreBackend = strings.ToLower(strings.TrimSpace(fileCfg.Traffic.StoreBackend))
	}
	if os.Getenv("DATABASE_URL") == "" && strings.TrimSpace(fileCfg.Traffic.DatabaseURL) != "" {
		cfg.DatabaseURL = fileCfg.Traffic.DatabaseURL
	}
	if os.Getenv("AUTO_MIGRATE") == "" && fileCfg.Traffic.AutoMigrate != nil {
		cfg.AutoMigrate = *fileCfg.Traffic.AutoMigrate
	}
	if os.Getenv("DB_WAIT_SECONDS") == "" && fileCfg.Traffic.DBWaitSeconds > 0 {
		cfg.DBWaitSeconds = fileCfg.Traffic.DBWaitSeconds
	}
	if os.Getenv("LLM_BASE_URL") == "" && strings.TrimSpace(fileCfg.Traffic.LLMBaseURL) != "" {
		cfg.LLMBaseURL = fileCfg.Traffic.LLMBaseURL
	}
	if os.Getenv("LLM_API_KEY") == "" && strings.TrimSpace(fileCfg.Traffic.LLMAPIKey) != "" {
		cfg.LLMAPIKey = fileCfg.Traffic.LLMAPIKey
	}
	if os.Getenv("LLM_MODEL") == "" && strings.TrimSpace(fileCfg.Traffic.LLMModel) != "" {
		cfg.LLMModel = fileCfg.Traffic.LLMModel
	}
	if os.Getenv("LLM_TIMEOUT_SECONDS") == "" && fileCfg.Traffic.LLMTimeoutSeconds > 0 {
		cfg.LLMTimeout = time.Duration(fileCfg.Traffic.LLMTimeoutSeconds) * time.Second
	}
}

func findConfigFile() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		path := filepath.Join(wd, "config.toml")
		if _, err := os.Stat(path); err == nil {
			return path
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return ""
		}
		wd = parent
	}
}

func upsertTOMLSectionValues(content, section string, values map[string]string, order []string) string {
	lines := strings.Split(content, "\n")
	if content == "" {
		lines = []string{}
	}
	header := "[" + section + "]"
	sectionStart := -1
	sectionEnd := len(lines)
	for i, line := range lines {
		if strings.TrimSpace(line) != header {
			continue
		}
		sectionStart = i
		for j := i + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				sectionEnd = j
				break
			}
		}
		break
	}

	if sectionStart < 0 {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, header)
		sectionStart = len(lines) - 1
		sectionEnd = len(lines)
	}

	seen := map[string]bool{}
	for i := sectionStart + 1; i < sectionEnd; i++ {
		key, ok := tomlLineKey(lines[i])
		if !ok {
			continue
		}
		value, exists := values[key]
		if !exists {
			continue
		}
		lines[i] = fmt.Sprintf("%-19s = %s", key, value)
		seen[key] = true
	}

	insert := []string{}
	for _, key := range order {
		value, ok := values[key]
		if ok && !seen[key] {
			insert = append(insert, fmt.Sprintf("%-19s = %s", key, value))
		}
	}
	if len(insert) > 0 {
		next := append([]string{}, lines[:sectionEnd]...)
		next = append(next, insert...)
		next = append(next, lines[sectionEnd:]...)
		lines = next
	}

	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

func tomlLineKey(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false
	}
	idx := strings.Index(trimmed, "=")
	if idx < 0 {
		return "", false
	}
	key := strings.TrimSpace(trimmed[:idx])
	if key == "" || strings.ContainsAny(key, " \t[]") {
		return "", false
	}
	return key, true
}

func quoteTOMLString(value string) string {
	return strconv.Quote(value)
}

func normalizeTimeout(value int) int {
	if value <= 0 {
		return 60
	}
	return value
}

func normalizeDBWait(value int) int {
	if value <= 0 {
		return 30
	}
	return value
}

func maskSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func get(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func getBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}
