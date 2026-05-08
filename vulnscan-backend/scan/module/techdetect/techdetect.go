package techdetect

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/engine"
	"vulnscan-backend/scan/rulestore"
)

type TechDetector struct {
	client *http.Client
	store  *rulestore.Store
}

func New(store *rulestore.Store) *TechDetector {
	return &TechDetector{
		store: store,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 5,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (m *TechDetector) ID() string       { return "tech_detect" }
func (m *TechDetector) Name() string     { return "技术栈检测" }
func (m *TechDetector) Category() string { return "recon" }

type detectResult struct {
	Name     string
	Category string
	Version  string
	Evidence string
}

func (m *TechDetector) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	rules := m.store.Get(model.RuleTypeTechDetect)
	if len(rules) == 0 {
		slog.Warn("[!] 技术栈检测无可用规则")
		return result, nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, t := range targets {
		base := buildBaseURL(t)
		if base == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *engine.Target, u string) {
			defer wg.Done()
			defer func() { <-sem }()

			techs := m.detectTech(ctx, u, rules)

			mu.Lock()
			for _, tech := range techs {
				title := tech.Name
				if tech.Version != "" {
					title = fmt.Sprintf("%s v%s", tech.Name, tech.Version)
				}
				result.Findings = append(result.Findings, &engine.Finding{
					ModuleID:   m.ID(),
					Target:     target,
					Type:       "tech_stack",
					Title:      fmt.Sprintf("[%s] %s", tech.Category, title),
					Severity:   "info",
					Confidence: 80,
					Timestamp:  time.Now(),
					Data: map[string]string{
						"name":     tech.Name,
						"category": tech.Category,
						"version":  tech.Version,
						"evidence": tech.Evidence,
					},
				})
			}
			mu.Unlock()
		}(t, base)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 技术栈检测完成",
		"targets", len(targets),
		"rules", len(rules),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *TechDetector) detectTech(ctx context.Context, baseURL string, rules []*rulestore.CompiledRule) []detectResult {
	resp := m.fetchPage(ctx, baseURL+"/")
	if resp == nil {
		return nil
	}

	detected := make(map[string]*detectResult)

	for _, r := range rules {
		matched, evidence := matchTechRule(r, resp)
		if !matched {
			continue
		}

		if _, exists := detected[r.Name]; exists {
			continue
		}

		version := ""
		if r.VersionRe != nil {
			full := resp.headerStr + "\n" + resp.body
			if sub := r.VersionRe.FindStringSubmatch(full); len(sub) > 1 {
				version = sub[1]
			}
		}

		detected[r.Name] = &detectResult{
			Name:     r.Name,
			Category: r.Category,
			Version:  version,
			Evidence: evidence,
		}

		for _, imp := range r.Implies {
			if _, exists := detected[imp]; !exists {
				detected[imp] = &detectResult{
					Name:     imp,
					Category: findCategory(imp, rules),
					Evidence: fmt.Sprintf("implied by %s", r.Name),
				}
			}
		}
	}

	var results []detectResult
	for _, dr := range detected {
		results = append(results, *dr)
	}
	return results
}

type pageResponse struct {
	statusCode int
	headers    http.Header
	headerStr  string
	cookies    []*http.Cookie
	body       string
}

func (m *TechDetector) fetchPage(ctx context.Context, rawURL string) *pageResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var hb strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			hb.WriteString(k)
			hb.WriteString(": ")
			hb.WriteString(v)
			hb.WriteString("\n")
		}
	}

	return &pageResponse{
		statusCode: resp.StatusCode,
		headers:    resp.Header,
		headerStr:  hb.String(),
		cookies:    resp.Cookies(),
		body:       string(body),
	}
}

func matchTechRule(r *rulestore.CompiledRule, resp *pageResponse) (bool, string) {
	switch r.MatchLocation {
	case model.MatchLocationHeader:
		if r.MatchKey != "" {
			val := resp.headers.Get(r.MatchKey)
			if val != "" && r.PatternRe.MatchString(val) {
				return true, fmt.Sprintf("header %s: %s", r.MatchKey, truncate(val, 60))
			}
		}

	case model.MatchLocationBody:
		if r.PatternRe.MatchString(resp.body) {
			match := r.PatternRe.FindString(resp.body)
			return true, fmt.Sprintf("body: %s", truncate(match, 60))
		}

	case model.MatchLocationMeta:
		if r.MatchKey != "" {
			metaPattern := regexp.MustCompile(fmt.Sprintf(
				`(?i)<meta[^>]+name=["']%s["'][^>]+content=["']([^"']+)["']`,
				regexp.QuoteMeta(r.MatchKey),
			))
			if sub := metaPattern.FindStringSubmatch(resp.body); len(sub) > 1 && r.PatternRe.MatchString(sub[1]) {
				return true, fmt.Sprintf("meta %s=%s", r.MatchKey, truncate(sub[1], 60))
			}
			metaReverse := regexp.MustCompile(fmt.Sprintf(
				`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']%s["']`,
				regexp.QuoteMeta(r.MatchKey),
			))
			if sub := metaReverse.FindStringSubmatch(resp.body); len(sub) > 1 && r.PatternRe.MatchString(sub[1]) {
				return true, fmt.Sprintf("meta %s=%s", r.MatchKey, truncate(sub[1], 60))
			}
		}

	case model.MatchLocationCookie:
		for _, c := range resp.cookies {
			cookieStr := c.Name + "=" + c.Value
			if r.PatternRe.MatchString(cookieStr) || r.PatternRe.MatchString(c.Name) {
				return true, fmt.Sprintf("cookie: %s", c.Name)
			}
		}

	case model.MatchLocationScript:
		if r.PatternRe.MatchString(resp.body) {
			match := r.PatternRe.FindString(resp.body)
			return true, fmt.Sprintf("script: %s", truncate(match, 60))
		}
	}

	return false, ""
}

func findCategory(name string, rules []*rulestore.CompiledRule) string {
	for _, r := range rules {
		if r.Name == name {
			return r.Category
		}
	}
	return "Misc"
}

func buildBaseURL(t *engine.Target) string {
	if t.URL != "" {
		return strings.TrimRight(t.URL, "/")
	}
	if t.Port <= 0 {
		return ""
	}
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	scheme := "http"
	if t.Port == 443 || t.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
