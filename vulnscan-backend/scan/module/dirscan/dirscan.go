package dirscan

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
	"sync/atomic"
	"time"

	"vulnscan-backend/dict"
	"vulnscan-backend/scan/engine"
)

type DirScanner struct {
	client    *http.Client
	dictStore *dict.Store
}

func New() *DirScanner {
	return NewWithDict(nil)
}

func NewWithDict(dictStore *dict.Store) *DirScanner {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	if dictStore == nil {
		dictStore = dict.NewStore(nil)
	}
	return &DirScanner{
		dictStore: dictStore,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (m *DirScanner) ID() string       { return "dir_scan" }
func (m *DirScanner) Name() string     { return "目录扫描" }
func (m *DirScanner) Category() string { return "recon" }

func (m *DirScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var scanned atomic.Int64

	wordlist := m.getWordlist(config)
	sem := make(chan struct{}, 30)

	for _, t := range targets {
		baseURL := buildBaseURL(t)
		if baseURL == "" {
			continue
		}

		baselineStatus, baselineLen := m.getBaseline(ctx, baseURL)

		for _, path := range wordlist {
			select {
			case <-ctx.Done():
				result.Duration = time.Since(start)
				return result, ctx.Err()
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(target *engine.Target, base, p string) {
				defer wg.Done()
				defer func() { <-sem }()

				scanned.Add(1)
				testURL := base + "/" + strings.TrimPrefix(p, "/")

				status, length, title := m.probe(ctx, testURL)
				if status <= 0 {
					return
				}

				if m.isInteresting(status, length, baselineStatus, baselineLen) {
					finding := &engine.Finding{
						ModuleID:   m.ID(),
						Target:     target,
						Type:       "directory",
						Title:      fmt.Sprintf("发现路径: %s [%d]", p, status),
						Severity:   m.classifySeverity(p, status),
						Confidence: 80,
						Timestamp:  time.Now(),
						Data: map[string]string{
							"path":   p,
							"url":    testURL,
							"status": fmt.Sprintf("%d", status),
							"length": fmt.Sprintf("%d", length),
							"title":  title,
						},
					}

					mu.Lock()
					result.Findings = append(result.Findings, finding)
					mu.Unlock()
				}
			}(t, baseURL, path)
		}
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 目录扫描完成",
		"targets", len(targets),
		"paths_scanned", scanned.Load(),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *DirScanner) probe(ctx context.Context, rawURL string) (int, int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	title := extractTitle(string(body))

	return resp.StatusCode, len(body), title
}

func (m *DirScanner) getBaseline(ctx context.Context, baseURL string) (int, int) {
	randomPath := baseURL + "/rAnD0m_pAtH_404_tEsT"
	status, length, _ := m.probe(ctx, randomPath)
	return status, length
}

func (m *DirScanner) isInteresting(status, length, baselineStatus, baselineLen int) bool {
	if status == 404 {
		return false
	}

	if status == baselineStatus && abs(length-baselineLen) < 50 {
		return false
	}

	interestingCodes := map[int]bool{
		200: true, 201: true, 301: true, 302: true,
		307: true, 308: true, 401: true, 403: true,
	}
	return interestingCodes[status]
}

func (m *DirScanner) classifySeverity(path string, status int) string {
	sensitivePatterns := []string{
		".git", ".svn", ".env", ".DS_Store",
		"wp-admin", "phpmyadmin", "adminer",
		"backup", ".bak", ".sql", ".dump",
		"config", "debug", "trace",
	}

	pathLower := strings.ToLower(path)
	for _, p := range sensitivePatterns {
		if strings.Contains(pathLower, p) {
			return "high"
		}
	}

	if status == 200 || status == 301 {
		return "medium"
	}
	return "low"
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

func extractTitle(body string) string {
	lowerBody := strings.ToLower(body)
	start := strings.Index(lowerBody, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lowerBody[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(body[start : start+end])
	if len(title) > 100 {
		title = title[:100]
	}
	return title
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (m *DirScanner) getWordlist(config map[string]interface{}) []string {
	if config != nil {
		if wl, ok := config["wordlist"].([]string); ok && len(wl) > 0 {
			return wl
		}
		if dictName, ok := config["dict_name"].(string); ok && dictName != "" {
			entries := m.dictStore.Get("dirpath", dictName)
			if len(entries) > 0 {
				return entries
			}
		}
	}
	return m.dictStore.GetDirpaths()
}
