package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	LLMTemperature          float64
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
		LLMTemperature:          1,
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

	next := upsertTOMLSectionValues(content, "traffic", replacements)
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		return LLMSettings{}, err
	}
	out := settings
	out.Model = firstNonEmpty(strings.TrimSpace(out.Model), "deepseek-chat")
	out.TimeoutSeconds = normalizeTimeout(out.TimeoutSeconds)
	out.ConfigPath = path
	out.APIKeyConfigured = strings.TrimSpace(out.APIKey) != ""
	out.APIKeyMasked = maskSecret(out.APIKey)
	return out, nil
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

func upsertTOMLSectionValues(content, section string, values map[string]string) string {
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
	for _, key := range []string{"llm_base_url", "llm_api_key", "llm_model", "llm_timeout_seconds"} {
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
