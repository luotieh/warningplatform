package traffic

import (
	"context"
	"net/http"
	"sync"
	"time"

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
