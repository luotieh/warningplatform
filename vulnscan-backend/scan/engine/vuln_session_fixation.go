package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SessionFixationScannerModule struct {
	scanner *VulnScanner
}

func NewSessionFixationScannerModule(scanner *VulnScanner) *SessionFixationScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "session-fixation-scanner"})
	}
	return &SessionFixationScannerModule{scanner: scanner}
}

func (m *SessionFixationScannerModule) ID() string       { return "session-fixation-scanner" }
func (m *SessionFixationScannerModule) Name() string     { return "Session Fixation Scanner" }
func (m *SessionFixationScannerModule) Category() string { return "web" }

func (m *SessionFixationScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	result := &ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 5)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		if target.URL == "" && target.Host != "" {
			target.URL = fmt.Sprintf("http://%s", target.Host)
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t *Target) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := m.scanTarget(ctx, t)
			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	slog.Info("[SessionFixation-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *SessionFixationScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	loginPaths := []string{"/login", "/signin", "/auth/login", "/api/login", "/admin/login"}

	for _, loginPath := range loginPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		loginURL := target.URL + loginPath

		req1, _ := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
		resp1, _, err := m.scanner.Client.FetchFull(req1)
		if err != nil {
			continue
		}

		var initialSessionID string
		for _, cookie := range resp1.Cookies() {
			if isSessionCookie(cookie.Name) {
				initialSessionID = cookie.Value
				break
			}
		}

		if initialSessionID == "" {
			continue
		}

		req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, nil)
		req2.AddCookie(&http.Cookie{Name: getSessionCookieName(resp1.Cookies()), Value: initialSessionID})
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp2, _, err := m.scanner.Client.FetchFull(req2)
		if err != nil {
			continue
		}

		var postLoginSessionID string
		for _, cookie := range resp2.Cookies() {
			if isSessionCookie(cookie.Name) {
				postLoginSessionID = cookie.Value
				break
			}
		}

		if postLoginSessionID == initialSessionID {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "session_fixation",
				Title:       "Session Fixation Vulnerability",
				Description: fmt.Sprintf("The application does not regenerate session ID after login at %s", loginURL),
				Severity:    "high",
				Confidence:  85,
				Evidence:    fmt.Sprintf("Session ID before and after login is the same: %s", initialSessionID[:min(16, len(initialSessionID))]),
				Timestamp:   time.Now(),
				Remediation: "Regenerate session ID after successful authentication",
				Data: map[string]string{
					"login_url": loginURL,
				},
			})

			break
		}
	}

	return findings
}

func isSessionCookie(name string) bool {
	sessionNames := []string{
		"session", "sessionid", "sid", "phpsessid", "jsessionid",
		"asp.net_sessionid", "connect.sid", "sess",
	}

	nameLower := strings.ToLower(name)
	for _, sn := range sessionNames {
		if strings.Contains(nameLower, sn) {
			return true
		}
	}

	return false
}

func getSessionCookieName(cookies []*http.Cookie) string {
	for _, cookie := range cookies {
		if isSessionCookie(cookie.Name) {
			return cookie.Name
		}
	}

	return "session"
}
