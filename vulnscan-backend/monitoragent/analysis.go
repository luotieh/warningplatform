package monitoragent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/analyzer"

	"gorm.io/gorm"
)

type AnalysisEngine struct {
	ruleFetcher RuleFetcher
	gormDB      *gorm.DB
	registry    *analyzer.Registry
	rules       *ruleStore

	mu          sync.RWMutex
	lastRefresh time.Time
}

type RuleFetcher interface {
	FetchRules(ctx context.Context) (map[string]json.RawMessage, error)
}

func NewAnalysisEngine(fetcher RuleFetcher) *AnalysisEngine {
	rs := &ruleStore{data: make(map[string][]byte)}
	reg := analyzer.NewRegistry()
	reg.Register(analyzer.NewSensitiveWordAnalyzer(rs))
	reg.Register(analyzer.NewBlacklinkAnalyzer(rs))
	reg.Register(analyzer.NewAvailabilityAnalyzer(rs))
	reg.Register(analyzer.NewDomainHijackAnalyzer(rs))

	return &AnalysisEngine{
		ruleFetcher: fetcher,
		registry:    reg,
		rules:       rs,
	}
}

func NewAnalysisEngineFromDB(db *gorm.DB) *AnalysisEngine {
	rs := &ruleStore{data: make(map[string][]byte)}
	reg := analyzer.NewRegistry()
	reg.Register(analyzer.NewSensitiveWordAnalyzer(rs))
	reg.Register(analyzer.NewBlacklinkAnalyzer(rs))
	reg.Register(analyzer.NewAvailabilityAnalyzer(rs))
	reg.Register(analyzer.NewDomainHijackAnalyzer(rs))

	return &AnalysisEngine{
		gormDB:   db,
		registry: reg,
		rules:    rs,
	}
}

func (e *AnalysisEngine) RefreshRules(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if time.Since(e.lastRefresh) < 60*time.Second {
		return
	}

	if e.gormDB != nil {
		e.refreshRulesFromDB()
	} else if e.ruleFetcher != nil {
		e.refreshRulesFromHTTP(ctx)
	}
	e.lastRefresh = time.Now()
}

func (e *AnalysisEngine) refreshRulesFromHTTP(ctx context.Context) {
	rules, err := e.ruleFetcher.FetchRules(ctx)
	if err != nil {
		slog.Warn("fetch rules failed", "error", err)
		return
	}

	newData := make(map[string][]byte, len(rules))
	for k, v := range rules {
		newData[k] = []byte(v)
	}
	e.rules.replace(newData)
	slog.Info("rules refreshed via HTTP", "count", len(newData))
}

func (e *AnalysisEngine) refreshRulesFromDB() {
	newData := make(map[string][]byte)

	// Load rule data
	var rules []model.MonitorRuleData
	if err := e.gormDB.Find(&rules).Error; err == nil {
		for _, r := range rules {
			if r.Data != "" {
				newData[r.ModuleKey] = []byte(r.Data)
			}
		}
	}

	// Load word libraries
	var wordLibs []model.MonitorWordLibrary
	e.gormDB.Find(&wordLibs)

	for _, lib := range wordLibs {
		var cats []model.MonitorWordCategory
		e.gormDB.Where("library_id = ?", lib.ID).Find(&cats)

		type entryOut struct {
			Word     string `json:"word"`
			Severity string `json:"severity"`
		}
		type catOut struct {
			Name    string     `json:"name"`
			Entries []entryOut `json:"entries"`
		}

		categories := make([]catOut, 0, len(cats))
		for _, cat := range cats {
			var entries []model.MonitorWordEntry
			e.gormDB.Where("category_id = ?", cat.ID).Find(&entries)
			eo := make([]entryOut, 0, len(entries))
			for _, e := range entries {
				eo = append(eo, entryOut{Word: e.Word, Severity: e.Severity})
			}
			categories = append(categories, catOut{Name: cat.Name, Entries: eo})
		}

		key := fmt.Sprintf("lib/word/%s", lib.ID)
		raw, _ := json.Marshal(map[string]any{
			"id":         lib.ID,
			"name":       lib.Name,
			"categories": categories,
		})
		newData[key] = raw
	}

	e.rules.replace(newData)
	slog.Info("rules refreshed from DB", "count", len(newData))
}

func (e *AnalysisEngine) Analyze(ctx context.Context, dimension, snapshotJSON, url string, task *TaskMessage) (string, error) {
	a, ok := e.registry.Get(dimension)
	if !ok {
		return snapshotJSON, nil
	}

	input := &analyzer.Input{
		ExecutionID:  task.ExecutionID,
		TaskID:       task.TaskID,
		URL:          url,
		SnapshotJSON: snapshotJSON,
	}

	output, err := a.Analyze(ctx, input)
	if err != nil {
		return "", fmt.Errorf("analyze %s: %w", dimension, err)
	}

	return e.formatResult(dimension, output, snapshotJSON), nil
}

func (e *AnalysisEngine) formatResult(dimension string, output *analyzer.Output, snapshotJSON string) string {
	switch dimension {
	case "sensitive_word":
		result := map[string]any{
			"has_hit":       output.HasIssue,
			"total_matches": 0,
			"matches":       []any{},
		}
		if output.DetailsJSON != "" {
			var details struct {
				Matches      []map[string]any `json:"matches"`
				TotalMatches int              `json:"total_matches"`
				TextLength   int              `json:"text_length"`
			}
			if err := json.Unmarshal([]byte(output.DetailsJSON), &details); err == nil {
				result["total_matches"] = details.TotalMatches
				result["preprocessing"] = map[string]any{"text_length": details.TextLength}
				matches := make([]map[string]any, 0, len(details.Matches))
				for _, m := range details.Matches {
					ctx, _ := m["context"].(string)
					contexts := []string{}
					if ctx != "" {
						contexts = []string{ctx}
					}
					matches = append(matches, map[string]any{
						"word":     m["word"],
						"category": m["category"],
						"severity": m["severity"],
						"count":    m["count"],
						"contexts": contexts,
					})
				}
				result["matches"] = matches
			}
		}
		raw, _ := json.Marshal(result)
		return string(raw)

	case "blacklink":
		result := map[string]any{"has_black": output.HasIssue}
		if output.DetailsJSON != "" {
			var details map[string]any
			if err := json.Unmarshal([]byte(output.DetailsJSON), &details); err == nil {
				for k, v := range details {
					result[k] = v
				}
			}
		}
		raw, _ := json.Marshal(result)
		return string(raw)

	case "availability":
		result := map[string]any{"available": !output.HasIssue}
		if output.DetailsJSON != "" {
			var details map[string]any
			if err := json.Unmarshal([]byte(output.DetailsJSON), &details); err == nil {
				for k, v := range details {
					result[k] = v
				}
			}
		}
		var snap map[string]any
		if err := json.Unmarshal([]byte(snapshotJSON), &snap); err == nil {
			for _, key := range []string{"dns_ms", "tcp_connect_ms", "tls_handshake_ms", "ttfb_ms", "total_ms", "status_code"} {
				if v, ok := snap[key]; ok {
					result[key] = v
				}
			}
		}
		raw, _ := json.Marshal(result)
		return string(raw)

	case "domain_hijack":
		result := map[string]any{"hijacked": output.HasIssue}
		if output.DetailsJSON != "" {
			var details map[string]any
			if err := json.Unmarshal([]byte(output.DetailsJSON), &details); err == nil {
				for k, v := range details {
					result[k] = v
				}
			}
		}
		raw, _ := json.Marshal(result)
		return string(raw)

	default:
		if output.DetailsJSON != "" {
			return output.DetailsJSON
		}
		return snapshotJSON
	}
}

// ruleStore implements analyzer.RuleAccessor
type ruleStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func (s *ruleStore) GetModuleRules(moduleKey string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.data[moduleKey]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", moduleKey)
	}
	return d, nil
}

func (s *ruleStore) GetAllRules() (map[string][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string][]byte, len(s.data))
	for k, v := range s.data {
		cp[k] = v
	}
	return cp, nil
}

func (s *ruleStore) replace(newData map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = newData
}
