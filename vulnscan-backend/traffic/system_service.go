package traffic

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/traffic/internal/client"
	trafficconfig "vulnscan-backend/traffic/internal/config"
	trafficservice "vulnscan-backend/traffic/internal/service"
)

const drivingModeStateKey = "driving_mode"

type SystemService struct {
	cfg    trafficconfig.Config
	core   trafficservice.Services
	state  map[string]bool
	stateM sync.RWMutex
}

func NewSystemService(cfg trafficconfig.Config, core trafficservice.Services) *SystemService {
	return &SystemService{
		cfg:   cfg,
		core:  core,
		state: map[string]bool{},
	}
}

func (s *SystemService) Health() map[string]any {
	return map[string]any{
		"ok":            true,
		"service":       "traffic-go",
		"status":        "ok",
		"store_backend": s.cfg.StoreBackend,
		"mq_backend":    s.cfg.MQBackend,
	}
}

func (s *SystemService) LLMHealth(ctx context.Context) any {
	return s.core.LLM.HealthCheck(ctx)
}

// LLMHealthTest 用配置页表单当前值（可能尚未保存）做健康检查。
// 空字段回退到已保存配置：api_key 表单以掩码展示不回传，为空即沿用已保存密钥，
// 与保存接口的语义一致。
func (s *SystemService) LLMHealthTest(ctx context.Context, baseURL, model, apiKey string, timeoutSeconds int) any {
	return s.core.LLM.WithOverrides(baseURL, model, apiKey, timeoutSeconds).HealthTest(ctx)
}

// TestLLMConfig 用表单传入的 base_url/model/api_key（未保存也生效）做一次真实健康探测。
// api_key 留空时沿用当前已保存的 key，便于"只改地址/模型先测试"的场景。
func (s *SystemService) TestLLMConfig(settings trafficconfig.LLMSettings) client.LLMHealth {
	probe := *s.core.LLM
	if strings.TrimSpace(settings.BaseURL) != "" {
		probe.BaseURL = strings.TrimSpace(settings.BaseURL)
	}
	if strings.TrimSpace(settings.APIKey) != "" {
		probe.APIKey = strings.TrimSpace(settings.APIKey)
	}
	if strings.TrimSpace(settings.Model) != "" {
		probe.Model = strings.TrimSpace(settings.Model)
	}
	timeout := time.Duration(settings.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	probe.HTTP = &http.Client{Timeout: timeout}
	return probe.HealthCheck(context.Background())
}

func (s *SystemService) LLMConfig() trafficconfig.LLMSettings {
	return trafficconfig.SettingsFromConfig(s.cfg)
}

func (s *SystemService) SetLLMConfig(settings trafficconfig.LLMSettings, updateAPIKey bool) (trafficconfig.LLMSettings, error) {
	updated, err := trafficconfig.WriteTrafficLLMSettings(settings, updateAPIKey)
	if err != nil {
		return trafficconfig.LLMSettings{}, err
	}
	s.cfg.LLMBaseURL = updated.BaseURL
	s.cfg.LLMAPIKey = updated.APIKey
	s.cfg.LLMModel = updated.Model
	s.cfg.LLMTimeout = time.Duration(updated.TimeoutSeconds) * time.Second
	s.core.LLM.BaseURL = updated.BaseURL
	s.core.LLM.APIKey = updated.APIKey
	s.core.LLM.Model = updated.Model
	s.core.LLM.HTTP = &http.Client{Timeout: s.cfg.LLMTimeout}
	return updated, nil
}

func (s *SystemService) StoreConfig() trafficconfig.StoreSettings {
	return trafficconfig.SettingsFromStoreConfig(s.cfg)
}

// SetStoreConfig 把 MySQL 配置写入 config.toml 并同步内存配置。
// 存储后端切换需重启进程生效（返回 RestartRequired 语义由 handler 提示）。
func (s *SystemService) SetStoreConfig(settings trafficconfig.StoreSettings, updatePassword bool) (trafficconfig.StoreSettings, error) {
	updated, err := trafficconfig.WriteTrafficStoreSettings(settings, updatePassword)
	if err != nil {
		return trafficconfig.StoreSettings{}, err
	}
	s.cfg.StoreBackend = updated.StoreBackend
	s.cfg.DatabaseURL = trafficconfig.BuildStoreDSN(updated)
	s.cfg.AutoMigrate = updated.AutoMigrate
	s.cfg.DBWaitSeconds = updated.DBWaitSeconds
	return updated, nil
}

func (s *SystemService) TestStoreConfig(settings trafficconfig.StoreSettings) trafficconfig.StoreTestResult {
	return trafficconfig.TestStoreSettings(settings)
}

func (s *SystemService) Version() map[string]any {
	return map[string]any{"version": "0.3.0-db-mq", "name": "traffic-go"}
}

func (s *SystemService) ReportGlobal() map[string]any {
	events := s.core.Store.ListEvents()
	return map[string]any{"event_count": len(events), "generated_at": time.Now().UTC()}
}

func (s *SystemService) PromptList() map[string]string {
	return trafficservice.DefaultPrompts
}

func (s *SystemService) Prompt(role string) map[string]string {
	return map[string]string{"role": role, "prompt": trafficservice.DefaultPrompt(role)}
}

func (s *SystemService) PromptBackground(name string) map[string]string {
	return map[string]string{"name": name, "content": trafficservice.DefaultPrompt("background_" + name)}
}

func (s *SystemService) GetDrivingMode(ctx context.Context) (bool, error) {
	s.setMemoryState(drivingModeStateKey, true)
	return true, nil
}

func (s *SystemService) SetDrivingMode(ctx context.Context, enabled bool) error {
	s.setMemoryState(drivingModeStateKey, true)
	return nil
}

func (s *SystemService) getMemoryState(key string) bool {
	s.stateM.RLock()
	defer s.stateM.RUnlock()
	return s.state[key]
}

func (s *SystemService) setMemoryState(key string, value bool) {
	s.stateM.Lock()
	defer s.stateM.Unlock()
	s.state[key] = value
}
