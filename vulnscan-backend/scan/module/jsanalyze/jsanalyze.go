package jsanalyze

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/engine"
	"vulnscan-backend/scan/rulestore"
)

type JSAnalyzer struct {
	client *http.Client
	store  *rulestore.Store
}

func New(store *rulestore.Store) *JSAnalyzer {
	return &JSAnalyzer{
		store: store,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}
}

func (m *JSAnalyzer) ID() string       { return "js_analyze" }
func (m *JSAnalyzer) Name() string     { return "JS 分析" }
func (m *JSAnalyzer) Category() string { return "recon" }

type JSFinding struct {
	RuleName   string
	Category   string
	Value      string
	Context    string
	Severity   string
	Confidence int
}

func (m *JSAnalyzer) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	rules := m.store.Get(model.RuleTypeJSAnalyze)
	if len(rules) == 0 {
		slog.Warn("[!] JS分析无可用规则")
		return result, nil
	}

	concurrency := parseInt(config, "concurrency", 20)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, t := range targets {
		jsURL := t.URL
		if jsURL == "" {
			continue
		}

		if !strings.HasSuffix(strings.ToLower(jsURL), ".js") && !strings.Contains(jsURL, ".js?") {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *engine.Target, u string) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := m.analyzeJS(ctx, u, rules)

			mu.Lock()
			for _, f := range findings {
				result.Findings = append(result.Findings, &engine.Finding{
					ModuleID:   m.ID(),
					Target:     target,
					Type:       f.Category,
					Title:      fmt.Sprintf("[JS][%s] %s", f.RuleName, truncate(f.Value, 80)),
					Severity:   f.Severity,
					Confidence: f.Confidence,
					Evidence:   truncate(f.Context, 200),
					Timestamp:  time.Now(),
					Data: map[string]string{
						"category":  f.Category,
						"rule_name": f.RuleName,
						"value":     f.Value,
						"js_url":    u,
					},
				})
			}
			mu.Unlock()
		}(t, jsURL)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] JS分析完成",
		"targets", len(targets),
		"rules", len(rules),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *JSAnalyzer) analyzeJS(ctx context.Context, jsURL string, rules []*rulestore.CompiledRule) []JSFinding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil
	}

	content := string(body)
	return extractFindings(content, rules)
}

func extractFindings(content string, rules []*rulestore.CompiledRule) []JSFinding {
	var findings []JSFinding
	seen := make(map[string]struct{})

	for _, r := range rules {
		matches := r.PatternRe.FindAllStringSubmatchIndex(content, 50)
		for _, loc := range matches {
			var value string
			if len(loc) >= 4 {
				value = content[loc[2]:loc[3]]
			} else {
				value = content[loc[0]:loc[1]]
			}

			key := r.Category + ":" + value
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			contextStart := loc[0] - 30
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := loc[1] + 30
			if contextEnd > len(content) {
				contextEnd = len(content)
			}

			findings = append(findings, JSFinding{
				RuleName:   r.Name,
				Category:   r.Category,
				Value:      value,
				Context:    content[contextStart:contextEnd],
				Severity:   r.Severity,
				Confidence: r.Confidence,
			})
		}
	}

	return findings
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func parseInt(config map[string]interface{}, key string, def int) int {
	if config != nil {
		if v, ok := config[key]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return def
}
