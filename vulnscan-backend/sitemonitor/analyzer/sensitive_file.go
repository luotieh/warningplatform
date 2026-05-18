package analyzer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vulnscan-backend/model"
)

type SensitiveFileAnalyzer struct {
	rules RuleAccessor
}

func NewSensitiveFileAnalyzer(rules RuleAccessor) *SensitiveFileAnalyzer {
	return &SensitiveFileAnalyzer{rules: rules}
}

func (a *SensitiveFileAnalyzer) Dimension() string { return "sensitive_file" }

func (a *SensitiveFileAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	baseURL := input.URL
	if baseURL == "" {
		return &Output{HasIssue: false}, nil
	}

	paths := a.loadProbePaths(input.Config)
	if len(paths) == 0 {
		paths = a.defaultProbePaths()
	}
	if len(paths) > 80 {
		paths = paths[:80]
	}

	client := &http.Client{Timeout: 12 * time.Second}
	findings := make([]model.MonitorSensitiveFileFinding, 0)
	riskSummary := map[string]int{}
	totalMs := 0

	for _, p := range paths {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		target, err := joinURL(baseURL, p.Path)
		if err != nil {
			continue
		}
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "VulnScan-Monitor/1.0")

		resp, err := client.Do(req)
		elapsed := time.Since(start).Milliseconds()
		totalMs += int(elapsed)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		if !isSensitiveFileHit(resp.StatusCode, len(body)) {
			continue
		}

		risk := p.Risk
		if risk == "" {
			risk = "high"
		}
		mark := p.Mark
		if mark == "" {
			mark = "敏感路径"
		}
		riskSummary[risk]++

		findings = append(findings, model.MonitorSensitiveFileFinding{
			URL:           target,
			Path:          p.Path,
			Mark:          mark,
			Risk:          risk,
			StatusCode:    resp.StatusCode,
			ContentLength: len(body),
			Detail:        truncate(string(body), 200),
			ElapsedMs:     float64(elapsed),
		})
	}

	hasHit := len(findings) > 0
	detail := model.MonitorSensitiveFileResult{
		URL:      baseURL,
		HasHit:   hasHit,
		Findings: findings,
		Stats: model.MonitorSensitiveFileStats{
			TotalChecked:  len(paths),
			TotalFindings: len(findings),
			TotalProbeMs:  totalMs,
			RiskSummary:   riskSummary,
		},
	}
	raw, _ := json.Marshal(detail)
	out := &Output{HasIssue: hasHit}
	if hasHit {
		out.Severity = "high"
	}
	out.DetailsJSON = string(raw)
	return out, nil
}

type probePath struct {
	Path string
	Mark string
	Risk string
}

func (a *SensitiveFileAnalyzer) loadProbePaths(cfg map[string]any) []probePath {
	ids := extractConfigStringSlice(cfg, "file_library_ids")
	if len(ids) == 0 {
		return nil
	}
	paths := make([]probePath, 0)
	for _, id := range ids {
		key := "lib/file/" + id
		data, err := a.rules.GetModuleRules(key)
		if err != nil || len(data) == 0 {
			continue
		}
		var lib struct {
			Entries []struct {
				Path string `json:"path"`
				Mark string `json:"mark"`
				Risk string `json:"risk"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(data, &lib); err != nil {
			continue
		}
		for _, e := range lib.Entries {
			if e.Path == "" {
				continue
			}
			paths = append(paths, probePath{Path: e.Path, Mark: e.Mark, Risk: e.Risk})
		}
	}
	return paths
}

func (a *SensitiveFileAnalyzer) defaultProbePaths() []probePath {
	data, err := a.rules.GetModuleRules("sf_engine")
	if err != nil || len(data) == 0 {
		return []probePath{
			{Path: "/.env", Mark: "环境变量", Risk: "critical"},
			{Path: "/.git/HEAD", Mark: "Git泄露", Risk: "critical"},
			{Path: "/robots.txt", Mark: "robots", Risk: "low"},
		}
	}
	var engine struct {
		HighRiskDirs []struct {
			Path string `json:"path"`
		} `json:"high_risk_dirs"`
	}
	if err := json.Unmarshal(data, &engine); err != nil {
		return nil
	}
	out := make([]probePath, 0, len(engine.HighRiskDirs))
	for _, d := range engine.HighRiskDirs {
		if d.Path != "" {
			out = append(out, probePath{Path: d.Path, Mark: "高风险目录", Risk: "high"})
		}
	}
	return out
}

func extractConfigStringSlice(cfg map[string]any, key string) []string {
	if cfg == nil {
		return nil
	}
	v, ok := cfg[key]
	if !ok {
		return nil
	}
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func joinURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return u.ResolveReference(ref).String(), nil
}

func isSensitiveFileHit(status int, bodyLen int) bool {
	if status == http.StatusOK && bodyLen > 0 {
		return true
	}
	if status == http.StatusForbidden || status == http.StatusUnauthorized {
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
