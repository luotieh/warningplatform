package emailcollect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type EmailCollector struct {
	client *http.Client
}

func New() *EmailCollector {
	return &EmailCollector{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (m *EmailCollector) ID() string       { return "email_collect" }
func (m *EmailCollector) Name() string     { return "邮箱收集" }
func (m *EmailCollector) Category() string { return "recon" }

var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func (m *EmailCollector) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	domain := parseString(config, "domain", "")
	if domain == "" && len(targets) > 0 {
		domain = targets[0].Host
	}
	if domain == "" {
		return result, fmt.Errorf("domain is required")
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	allEmails := make(map[string]string)

	collectors := []struct {
		name string
		fn   func(ctx context.Context, domain string) map[string]string
	}{
		{"Bing", m.bingEmails},
		{"Google CSE", m.googleEmails},
		{"PGP Server", m.pgpEmails},
		{"crt.sh", m.crtShEmails},
	}

	for _, c := range collectors {
		wg.Add(1)
		go func(name string, fn func(ctx context.Context, domain string) map[string]string) {
			defer wg.Done()
			emails := fn(ctx, domain)
			mu.Lock()
			for email, source := range emails {
				if _, ok := allEmails[email]; ok {
					allEmails[email] += "," + source
				} else {
					allEmails[email] = source
				}
			}
			mu.Unlock()
			slog.Info("[+] 邮箱收集器完成", "collector", name, "found", len(emails))
		}(c.name, c.fn)
	}

	wg.Wait()

	for email, source := range allEmails {
		result.Findings = append(result.Findings, &core.Finding{
			ModuleID:   m.ID(),
			Type:       "email",
			Title:      fmt.Sprintf("发现邮箱: %s", email),
			Severity:   "info",
			Confidence: 80,
			Timestamp:  time.Now(),
			Data:       map[string]string{"email": email, "source": source, "domain": domain},
		})
	}

	result.Duration = time.Since(start)
	slog.Info("[+] 邮箱收集完成", "domain", domain, "total", len(allEmails), "duration", result.Duration)
	return result, nil
}

func (m *EmailCollector) bingEmails(ctx context.Context, domain string) map[string]string {
	results := make(map[string]string)
	queries := []string{
		fmt.Sprintf(`"@%s" email`, domain),
		fmt.Sprintf(`site:%s email`, domain),
	}

	for _, q := range queries {
		searchURL := fmt.Sprintf("https://www.bing.com/search?q=%s&count=50", url.QueryEscape(q))
		body := m.fetchPage(ctx, searchURL)
		for _, email := range extractEmails(body, domain) {
			results[email] = "bing"
		}
	}
	return results
}

func (m *EmailCollector) googleEmails(ctx context.Context, domain string) map[string]string {
	results := make(map[string]string)
	searchURL := fmt.Sprintf("https://www.google.com/search?q=\"@%s\"&num=100", url.QueryEscape(domain))
	body := m.fetchPage(ctx, searchURL)
	for _, email := range extractEmails(body, domain) {
		results[email] = "google"
	}
	return results
}

func (m *EmailCollector) pgpEmails(ctx context.Context, domain string) map[string]string {
	results := make(map[string]string)
	searchURL := fmt.Sprintf("https://pgp.mit.edu/pks/lookup?search=%s&op=index", url.QueryEscape(domain))
	body := m.fetchPage(ctx, searchURL)
	for _, email := range extractEmails(body, domain) {
		results[email] = "pgp"
	}
	return results
}

func (m *EmailCollector) crtShEmails(ctx context.Context, domain string) map[string]string {
	results := make(map[string]string)
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return results
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return results
	}

	for _, e := range entries {
		for _, email := range extractEmails(e.NameValue, domain) {
			results[email] = "crt.sh"
		}
	}
	return results
}

func (m *EmailCollector) fetchPage(ctx context.Context, rawURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := m.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	return string(body)
}

func extractEmails(content, domain string) []string {
	matches := emailRe.FindAllString(content, -1)
	var filtered []string
	seen := make(map[string]struct{})
	for _, e := range matches {
		e = strings.ToLower(e)
		if strings.HasSuffix(e, "@"+domain) {
			if _, ok := seen[e]; !ok {
				seen[e] = struct{}{}
				filtered = append(filtered, e)
			}
		}
	}
	return filtered
}

func parseString(config map[string]interface{}, key, def string) string {
	if config != nil {
		if v, ok := config[key].(string); ok {
			return v
		}
	}
	return def
}
