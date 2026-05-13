package wafdetect

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
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/rulestore"
)

type WAFDetector struct {
	client *http.Client
	store  *rulestore.Store
}

func New(store *rulestore.Store) *WAFDetector {
	return &WAFDetector{
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

func (m *WAFDetector) ID() string       { return "waf_detect" }
func (m *WAFDetector) Name() string     { return "WAF 检测" }
func (m *WAFDetector) Category() string { return "recon" }

var testPayloads = []string{
	"/<script>alert(1)</script>",
	"/?id=1' OR '1'='1",
	"/../../etc/passwd",
	"/?cmd=cat+/etc/passwd",
}

func (m *WAFDetector) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	rules := m.store.Get(model.RuleTypeWAFDetect)
	if len(rules) == 0 {
		slog.Warn("[!] WAF检测无可用规则")
		return result, nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, t := range targets {
		baseURL := buildBaseURL(t)
		if baseURL == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *core.Target, base string) {
			defer wg.Done()
			defer func() { <-sem }()

			detected := m.detect(ctx, base, rules)

			mu.Lock()
			for _, waf := range detected {
				result.Findings = append(result.Findings, &core.Finding{
					ModuleID:   m.ID(),
					Target:     target,
					Type:       "waf",
					Title:      fmt.Sprintf("检测到WAF: %s", waf.name),
					Severity:   "info",
					Confidence: waf.confidence,
					Timestamp:  time.Now(),
					Data: map[string]string{
						"waf":      waf.name,
						"category": waf.category,
						"method":   waf.method,
						"evidence": waf.evidence,
					},
				})
			}
			mu.Unlock()
		}(t, baseURL)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] WAF检测完成",
		"targets", len(targets),
		"rules", len(rules),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

type wafResult struct {
	name       string
	category   string
	confidence int
	method     string
	evidence   string
}

func (m *WAFDetector) detect(ctx context.Context, baseURL string, rules []*rulestore.CompiledRule) []wafResult {
	var results []wafResult
	seen := make(map[string]struct{})

	normalResp := m.fetchResponse(ctx, baseURL+"/")
	if normalResp != nil {
		for _, r := range rules {
			if matched, evidence := matchRule(r, normalResp); matched {
				if _, ok := seen[r.Name]; !ok {
					seen[r.Name] = struct{}{}
					results = append(results, wafResult{
						name:       r.Name,
						category:   r.Category,
						confidence: r.Confidence,
						method:     "passive_header",
						evidence:   evidence,
					})
				}
			}
		}
	}

	for _, payload := range testPayloads {
		resp := m.fetchResponse(ctx, baseURL+payload)
		if resp == nil {
			continue
		}

		if resp.statusCode == 403 || resp.statusCode == 406 || resp.statusCode == 429 || resp.statusCode == 503 {
			for _, r := range rules {
				if matched, evidence := matchRule(r, resp); matched {
					if _, ok := seen[r.Name]; !ok {
						seen[r.Name] = struct{}{}
						results = append(results, wafResult{
							name:       r.Name,
							category:   r.Category,
							confidence: min(r.Confidence+5, 99),
							method:     "active_trigger",
							evidence:   evidence,
						})
					}
				}
			}

			if len(results) == 0 {
				results = append(results, wafResult{
					name:       "Unknown WAF",
					category:   "unknown",
					confidence: 60,
					method:     "status_code",
					evidence:   fmt.Sprintf("status=%d on payload", resp.statusCode),
				})
			}
			break
		}
	}

	return results
}

type httpResponse struct {
	statusCode int
	headers    http.Header
	cookies    []*http.Cookie
	body       string
}

func (m *WAFDetector) fetchResponse(ctx context.Context, rawURL string) *httpResponse {
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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	return &httpResponse{
		statusCode: resp.StatusCode,
		headers:    resp.Header,
		cookies:    resp.Cookies(),
		body:       string(body),
	}
}

func matchRule(r *rulestore.CompiledRule, resp *httpResponse) (bool, string) {
	switch r.MatchLocation {
	case model.MatchLocationHeader:
		if r.MatchKey != "" {
			val := resp.headers.Get(r.MatchKey)
			if val != "" && r.PatternRe.MatchString(val) {
				return true, fmt.Sprintf("header %s: %s", r.MatchKey, truncate(val, 60))
			}
		} else {
			for k, vs := range resp.headers {
				for _, v := range vs {
					if r.PatternRe.MatchString(v) {
						return true, fmt.Sprintf("header %s: %s", k, truncate(v, 60))
					}
				}
			}
		}

	case model.MatchLocationCookie:
		for _, c := range resp.cookies {
			cookieStr := c.Name + "=" + c.Value
			if r.PatternRe.MatchString(cookieStr) || r.PatternRe.MatchString(c.Name) {
				return true, fmt.Sprintf("cookie: %s", c.Name)
			}
		}

	case model.MatchLocationBody:
		if r.PatternRe.MatchString(resp.body) {
			match := r.PatternRe.FindString(resp.body)
			return true, fmt.Sprintf("body: %s", truncate(match, 50))
		}
	}

	return false, ""
}

func buildBaseURL(t *core.Target) string {
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
