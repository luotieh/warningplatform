package scanrunner

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"code.yt-security.com/public/scanengine/core"
	"gorm.io/gorm"
)

// FPSuppressor performs intelligent false-positive suppression based on
// confidence scoring, historical FP rates, and heuristic rules.
type FPSuppressor struct {
	db            *gorm.DB
	historicalFPs map[string]float64
	mu            sync.RWMutex
	stats         FPSuppressorStats
}

type FPSuppressorStats struct {
	Total      int `json:"total"`
	Suppressed int `json:"suppressed"`
	Demoted    int `json:"demoted"`
	Passed     int `json:"passed"`
}

func NewFPSuppressor(db *gorm.DB) *FPSuppressor {
	fps := &FPSuppressor{
		db:            db,
		historicalFPs: make(map[string]float64),
	}
	fps.loadHistoricalFPRates()
	return fps
}

// loadHistoricalFPRates queries past findings that were marked as false positive
// and computes per-module per-type FP rate.
func (s *FPSuppressor) loadHistoricalFPRates() {
	if s.db == nil {
		return
	}

	type fpStat struct {
		ModuleID   string
		Type       string
		Total      int64
		FalseCount int64
	}

	var stats []fpStat
	s.db.Raw(`
		SELECT module_id, type,
			COUNT(*) AS total,
			SUM(CASE WHEN is_false_positive = 1 THEN 1 ELSE 0 END) AS false_count
		FROM scan_findings
		WHERE created_at > DATE_SUB(NOW(), INTERVAL 90 DAY)
		GROUP BY module_id, type
		HAVING total >= 5
	`).Scan(&stats)

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, st := range stats {
		if st.Total > 0 {
			key := st.ModuleID + ":" + st.Type
			rate := float64(st.FalseCount) / float64(st.Total)
			s.historicalFPs[key] = rate
		}
	}

	slog.Info("[FPSuppressor] 加载历史误报率",
		"module_types", len(s.historicalFPs))
}

// SuppressFindings applies multi-layered false positive detection.
func (s *FPSuppressor) SuppressFindings(findings []*core.Finding) []*core.Finding {
	if len(findings) == 0 {
		return findings
	}

	s.stats = FPSuppressorStats{Total: len(findings)}

	result := make([]*core.Finding, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}

		action := s.evaluate(f)
		switch action {
		case fpActionPass:
			s.stats.Passed++
			result = append(result, f)
		case fpActionDemote:
			s.stats.Demoted++
			f.Severity = demoteSeverity(f.Severity)
			if f.Confidence > 30 {
				f.Confidence = 30
			}
			f.ConfidenceReason = appendReason(f.ConfidenceReason, "高历史误报率模块")
			result = append(result, f)
		case fpActionSuppress:
			s.stats.Suppressed++
		}
	}

	if s.stats.Suppressed > 0 || s.stats.Demoted > 0 {
		slog.Info("[FPSuppressor] 误报抑制完成",
			"total", s.stats.Total,
			"passed", s.stats.Passed,
			"demoted", s.stats.Demoted,
			"suppressed", s.stats.Suppressed,
		)
	}

	return result
}

type fpAction int

const (
	fpActionPass fpAction = iota
	fpActionDemote
	fpActionSuppress
)

func (s *FPSuppressor) evaluate(f *core.Finding) fpAction {
	cat := inferCategory(f)
	if cat != "vuln" {
		return fpActionPass
	}

	if action := s.checkHeuristicRules(f); action != fpActionPass {
		return action
	}

	if action := s.checkHistoricalRate(f); action != fpActionPass {
		return action
	}

	if action := s.checkConfidenceThreshold(f); action != fpActionPass {
		return action
	}

	return fpActionPass
}

func (s *FPSuppressor) checkHeuristicRules(f *core.Finding) fpAction {
	title := strings.ToLower(f.Title)
	desc := strings.ToLower(f.Description)
	combined := title + " " + desc

	genericFPPatterns := []string{
		"possible", "potential", "may be", "might be",
		"可能存在", "疑似", "待验证",
	}
	for _, p := range genericFPPatterns {
		if strings.Contains(combined, p) && !f.Verified {
			return fpActionDemote
		}
	}

	if f.Evidence == "" && !f.Verified && f.Confidence < 50 {
		return fpActionSuppress
	}

	if isGenericInfoLeak(f) {
		return fpActionDemote
	}

	return fpActionPass
}

func (s *FPSuppressor) checkHistoricalRate(f *core.Finding) fpAction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := f.ModuleID + ":" + f.Type
	rate, exists := s.historicalFPs[key]
	if !exists {
		return fpActionPass
	}

	if rate >= 0.8 {
		return fpActionSuppress
	}
	if rate >= 0.5 {
		return fpActionDemote
	}

	return fpActionPass
}

func (s *FPSuppressor) checkConfidenceThreshold(f *core.Finding) fpAction {
	if f.Confidence <= 0 {
		return fpActionPass
	}
	if f.Confidence < 20 {
		return fpActionSuppress
	}
	if f.Confidence < 40 && !f.Verified {
		return fpActionDemote
	}
	return fpActionPass
}

func isGenericInfoLeak(f *core.Finding) bool {
	if f.Type != "info_leak" && f.Type != "sensitive_info" {
		return false
	}

	title := strings.ToLower(f.Title)
	genericPatterns := []string{
		"server header", "x-powered-by", "technology detected",
		"framework detected", "server banner",
	}
	for _, p := range genericPatterns {
		if strings.Contains(title, p) {
			return true
		}
	}

	return false
}

func appendReason(existing, addition string) string {
	if existing == "" {
		return addition
	}
	return fmt.Sprintf("%s; %s", existing, addition)
}

func (s *FPSuppressor) Stats() FPSuppressorStats {
	return s.stats
}
