package gitleak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type GitLeakScanner struct {
	client *http.Client
	token  string
}

func New(githubToken string) *GitLeakScanner {
	return &GitLeakScanner{
		token: githubToken,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (m *GitLeakScanner) ID() string       { return "git_leak" }
func (m *GitLeakScanner) Name() string     { return "GitHub 泄露扫描" }
func (m *GitLeakScanner) Category() string { return "recon" }

type leakRule struct {
	name     string
	pattern  *regexp.Regexp
	severity string
}

var leakPatterns = []leakRule{
	{"AWS Access Key", regexp.MustCompile(`(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}`), "critical"},
	{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`), "critical"},
	{"GitHub Token", regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`), "high"},
	{"Slack Token", regexp.MustCompile(`xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+`), "high"},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), "high"},
	{"JWT", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`), "high"},
	{"Database URL", regexp.MustCompile(`(?i)(?:mysql|postgres|mongodb|redis)://[^\s"']+`), "high"},
	{"Password in Config", regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token)\s*[=:]\s*["']?[^\s"']{8,}["']?`), "medium"},
	{"Internal IP", regexp.MustCompile(`\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`), "medium"},
	{"API Endpoint", regexp.MustCompile(`(?i)https?://(?:api|internal|staging|dev)\.[a-z0-9.-]+`), "low"},
}

func (m *GitLeakScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	org := parseString(config, "organization", "")
	domain := parseString(config, "domain", "")
	maxResults := parseInt(config, "max_results", 100)

	if org == "" && domain == "" && len(targets) > 0 {
		domain = targets[0].Host
	}

	if m.token == "" {
		slog.Warn("[!] GitHub Token 未配置，搜索将受到速率限制")
	}

	var queries []string
	if org != "" {
		queries = append(queries, fmt.Sprintf("org:%s password", org))
		queries = append(queries, fmt.Sprintf("org:%s secret", org))
		queries = append(queries, fmt.Sprintf("org:%s api_key", org))
		queries = append(queries, fmt.Sprintf("org:%s token", org))
	}
	if domain != "" {
		queries = append(queries, fmt.Sprintf(`"%s" password`, domain))
		queries = append(queries, fmt.Sprintf(`"%s" secret`, domain))
		queries = append(queries, fmt.Sprintf(`"%s" api_key`, domain))
		queries = append(queries, fmt.Sprintf(`"%s" token`, domain))
		queries = append(queries, fmt.Sprintf(`"%s" database`, domain))
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	seen := make(map[string]struct{})
	perQuery := maxResults / max(len(queries), 1)

	sem := make(chan struct{}, 3)
	for _, q := range queries {
		wg.Add(1)
		go func(query string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			items := m.searchGitHub(ctx, query, perQuery)
			for _, item := range items {
				select {
				case <-ctx.Done():
					return
				default:
				}

				findings := m.analyzeContent(item)

				mu.Lock()
				for _, f := range findings {
					key := f.Data["rule"] + ":" + f.Data["value"]
					if _, ok := seen[key]; !ok {
						seen[key] = struct{}{}
						result.Findings = append(result.Findings, f)
					}
				}
				mu.Unlock()
			}

			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}(q)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] GitHub泄露扫描完成",
		"queries", len(queries),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

type searchItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
	TextMatches []struct {
		Fragment string `json:"fragment"`
	} `json:"text_matches"`
}

func (m *GitLeakScanner) searchGitHub(ctx context.Context, query string, maxResults int) []searchItem {
	perPage := 30
	if maxResults < perPage {
		perPage = maxResults
	}

	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=%d",
		url.QueryEscape(query), perPage)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github.v3.text-match+json")
	req.Header.Set("User-Agent", "VulnScan-GitLeakScanner")
	if m.token != "" {
		req.Header.Set("Authorization", "Bearer "+m.token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		slog.Debug("GitHub search failed", "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		slog.Debug("GitHub API error", "status", resp.StatusCode, "body", string(body))
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))

	var result struct {
		Items []searchItem `json:"items"`
		Total int          `json:"total_count"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	return result.Items
}

func (m *GitLeakScanner) analyzeContent(item searchItem) []*core.Finding {
	var findings []*core.Finding

	var content string
	for _, tm := range item.TextMatches {
		content += tm.Fragment + "\n"
	}

	for _, rule := range leakPatterns {
		matches := rule.pattern.FindAllString(content, 5)
		for _, match := range matches {
			findings = append(findings, &core.Finding{
				ModuleID:   "git_leak",
				Type:       "code_leak",
				Title:      fmt.Sprintf("[GitHub] %s in %s", rule.name, item.Repository.FullName),
				Severity:   rule.severity,
				Confidence: 75,
				Evidence:   truncate(match, 100),
				Timestamp:  time.Now(),
				Data: map[string]string{
					"rule":     rule.name,
					"value":    truncate(match, 200),
					"repo":     item.Repository.FullName,
					"file":     item.Path,
					"url":      item.HTMLURL,
					"repo_url": item.Repository.HTMLURL,
				},
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

func parseString(config map[string]interface{}, key, def string) string {
	if config != nil {
		if v, ok := config[key].(string); ok {
			return v
		}
	}
	return def
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
