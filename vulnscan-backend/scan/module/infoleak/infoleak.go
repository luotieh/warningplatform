package infoleak

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

	"vulnscan-backend/scan/engine"
)

type InfoLeakScanner struct {
	client *http.Client
}

func New() *InfoLeakScanner {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &InfoLeakScanner{
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (m *InfoLeakScanner) ID() string       { return "info_leak" }
func (m *InfoLeakScanner) Name() string     { return "信息泄露检测" }
func (m *InfoLeakScanner) Category() string { return "vuln" }

type leakCheck struct {
	Path     string
	Name     string
	Severity string
	Matchers []leakMatcher
}

type leakMatcher struct {
	Type    string
	Pattern *regexp.Regexp
	Header  string
	Value   string
}

func (m *InfoLeakScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	checks := builtinChecks()
	sem := make(chan struct{}, 20)

	for _, t := range targets {
		baseURL := buildBaseURL(t)
		if baseURL == "" {
			continue
		}

		for _, check := range checks {
			wg.Add(1)
			sem <- struct{}{}
			go func(target *engine.Target, base string, chk leakCheck) {
				defer wg.Done()
				defer func() { <-sem }()

				testURL := base + "/" + strings.TrimPrefix(chk.Path, "/")
				if finding := m.testLeak(ctx, target, testURL, chk); finding != nil {
					mu.Lock()
					result.Findings = append(result.Findings, finding)
					mu.Unlock()
				}
			}(t, baseURL, check)
		}
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 信息泄露检测完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *InfoLeakScanner) testLeak(ctx context.Context, target *engine.Target, rawURL string, check leakCheck) *engine.Finding {
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

	if resp.StatusCode != 200 {
		return nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}
	body := string(bodyBytes)

	for _, matcher := range check.Matchers {
		matched := false
		var evidence string

		switch matcher.Type {
		case "body_regex":
			if matcher.Pattern.MatchString(body) {
				matched = true
				if m := matcher.Pattern.FindString(body); m != "" {
					evidence = truncate(m, 200)
				}
			}
		case "body_contains":
			if strings.Contains(body, matcher.Value) {
				matched = true
				idx := strings.Index(body, matcher.Value)
				start := max(0, idx-50)
				end := min(len(body), idx+len(matcher.Value)+50)
				evidence = body[start:end]
			}
		case "header":
			if val := resp.Header.Get(matcher.Header); val != "" {
				if matcher.Value == "" || strings.Contains(val, matcher.Value) {
					matched = true
					evidence = fmt.Sprintf("%s: %s", matcher.Header, val)
				}
			}
		}

		if matched {
			return &engine.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "info_leak",
				Title:       check.Name,
				Description: fmt.Sprintf("在 %s 检测到信息泄露", check.Path),
				Severity:    check.Severity,
				Confidence:  85,
				Evidence:    truncate(evidence, 500),
				Timestamp:   time.Now(),
				Data: map[string]string{
					"path": check.Path,
					"url":  rawURL,
				},
			}
		}
	}

	return nil
}

func builtinChecks() []leakCheck {
	return []leakCheck{
		{
			Path: ".git/HEAD", Name: "Git仓库泄露", Severity: "high",
			Matchers: []leakMatcher{
				{Type: "body_regex", Pattern: regexp.MustCompile(`^ref: refs/`)},
			},
		},
		{
			Path: ".svn/entries", Name: "SVN仓库泄露", Severity: "high",
			Matchers: []leakMatcher{
				{Type: "body_regex", Pattern: regexp.MustCompile(`^\d+`)},
			},
		},
		{
			Path: ".env", Name: "环境变量文件泄露", Severity: "critical",
			Matchers: []leakMatcher{
				{Type: "body_regex", Pattern: regexp.MustCompile(`(?i)(DB_|DATABASE_|REDIS_|SECRET|KEY|TOKEN|PASSWORD|AWS_)\w*=`)},
			},
		},
		{
			Path: "phpinfo.php", Name: "PHPInfo页面", Severity: "medium",
			Matchers: []leakMatcher{
				{Type: "body_contains", Value: "PHP Version"},
				{Type: "body_contains", Value: "phpinfo()"},
			},
		},
		{
			Path: "actuator/env", Name: "Spring Actuator环境泄露", Severity: "high",
			Matchers: []leakMatcher{
				{Type: "body_regex", Pattern: regexp.MustCompile(`"activeProfiles"|"propertySources"`)},
			},
		},
		{
			Path: "actuator/heapdump", Name: "Spring Actuator堆转储", Severity: "critical",
			Matchers: []leakMatcher{
				{Type: "header", Header: "Content-Type", Value: "application/octet-stream"},
			},
		},
		{
			Path: "api/swagger.json", Name: "Swagger API文档泄露", Severity: "medium",
			Matchers: []leakMatcher{
				{Type: "body_regex", Pattern: regexp.MustCompile(`"swagger"|"openapi"`)},
			},
		},
		{
			Path: "server-status", Name: "Apache Server Status", Severity: "medium",
			Matchers: []leakMatcher{
				{Type: "body_contains", Value: "Apache Server Status"},
			},
		},
		{
			Path: ".DS_Store", Name: "macOS DS_Store文件", Severity: "low",
			Matchers: []leakMatcher{
				{Type: "body_regex", Pattern: regexp.MustCompile(`Bud1`)},
			},
		},
		{
			Path: "WEB-INF/web.xml", Name: "Java WEB-INF泄露", Severity: "high",
			Matchers: []leakMatcher{
				{Type: "body_regex", Pattern: regexp.MustCompile(`<web-app`)},
			},
		},
		{
			Path: "crossdomain.xml", Name: "Flash跨域策略", Severity: "low",
			Matchers: []leakMatcher{
				{Type: "body_regex", Pattern: regexp.MustCompile(`allow-access-from\s+domain="\*"`)},
			},
		},
		{
			Path: "debug/pprof/", Name: "Go pprof调试端点", Severity: "high",
			Matchers: []leakMatcher{
				{Type: "body_contains", Value: "Types of profiles available"},
			},
		},
	}
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
