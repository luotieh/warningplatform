package vulnkit

import (
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/scanhttp"

	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type VulnScanner struct {
	Client      *scanhttp.ScanHTTPClient
	Concurrency int
	pool        *scanhttp.ClientPool
	poolKey     string
}

func NewVulnScanner(config map[string]interface{}, moduleOpts ...scanhttp.ClientOption) *VulnScanner {
	concurrency := core.GetConfigInt(config, "concurrency", 10)

	pool := scanhttp.GetGlobalClientPool()
	poolKey := ""
	if name, ok := config["module_name"].(string); ok {
		poolKey = name
	}

	var client *scanhttp.ScanHTTPClient
	if len(moduleOpts) > 0 || poolKey != "" {
		opts := append(scanhttp.ClientFromConfig(config), moduleOpts...)
		client = pool.GetOrCreate(poolKey, opts...)
	} else {
		client = pool.GetDefault()
	}

	return &VulnScanner{
		Client:      client,
		Concurrency: concurrency,
		pool:        pool,
		poolKey:     poolKey,
	}
}

type TargetTestFunc func(ctx context.Context, target *core.Target) []*core.Finding

func (vs *VulnScanner) RunTargets(ctx context.Context, moduleID string, targets []*core.Target, testFn TargetTestFunc) *core.ModuleResult {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: moduleID}

	eligible := make([]*core.Target, 0, len(targets))
	skipped := 0
	for _, t := range targets {
		if t.URL == "" {
			skipped++
			continue
		}
		eligible = append(eligible, t)
	}

	if len(eligible) == 0 {
		result.Duration = time.Since(start)
		if skipped > 0 {
			slog.Debug("[VulnScanner] 无可用目标", "module", moduleID, "skipped", skipped)
		}
		return result
	}

	allFindings := make([]*core.Finding, 0, len(eligible))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, vs.Concurrency)
	var errCount int

	for _, t := range eligible {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err().Error()
			result.Duration = time.Since(start)
			return result
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(target *core.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			defer func() {
				if r := recover(); r != nil {
					slog.Error("[VulnScanner] panic in testFn",
						"module", moduleID,
						"target", target.Host,
						"panic", r,
					)
					mu.Lock()
					errCount++
					mu.Unlock()
				}
			}()

			findings := testFn(ctx, target)
			if len(findings) > 0 {
				mu.Lock()
				allFindings = append(allFindings, findings...)
				mu.Unlock()
			}
		}(t)
	}

	wg.Wait()
	result.Findings = allFindings
	result.Duration = time.Since(start)

	if errCount > 0 {
		slog.Warn("[VulnScanner] 部分目标出错",
			"module", moduleID,
			"errors", errCount,
			"total", len(eligible),
		)
	}

	return result
}

func (vs *VulnScanner) FetchBody(ctx context.Context, rawURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	body, _, err := vs.Client.Fetch(req)
	if err != nil {
		return ""
	}
	return body
}

func (vs *VulnScanner) FetchWithStatus(ctx context.Context, rawURL string) (string, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0
	}
	body, status, err := vs.Client.Fetch(req)
	if err != nil {
		return "", 0
	}
	return body, status
}

func (vs *VulnScanner) SendInjected(ctx context.Context, target *core.Target, point InjectionPoint, payload string) (string, int, error) {
	req, err := BuildInjectedRequest(ctx, target, point, payload)
	if err != nil {
		return "", 0, err
	}
	return vs.Client.Fetch(req)
}

func (vs *VulnScanner) SendInjectedFull(ctx context.Context, target *core.Target, point InjectionPoint, payload string) (*http.Response, string, error) {
	req, err := BuildInjectedRequest(ctx, target, point, payload)
	if err != nil {
		return nil, "", err
	}
	return vs.Client.FetchFull(req)
}

func (vs *VulnScanner) FetchFullResponse(ctx context.Context, rawURL string) (*http.Response, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, ""
	}
	resp, body, err := vs.Client.FetchFull(req)
	if err != nil {
		return nil, ""
	}
	return resp, body
}

func (vs *VulnScanner) SendJSON(ctx context.Context, rawURL, jsonPayload string) (string, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewBufferString(jsonPayload))
	if err != nil {
		return "", 0
	}
	req.Header.Set("Content-Type", "application/json")
	body, status, err := vs.Client.Fetch(req)
	if err != nil {
		return "", 0
	}
	return body, status
}

func (vs *VulnScanner) SendXML(ctx context.Context, rawURL, xmlPayload string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewBufferString(xmlPayload))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/xml")
	body, _, err := vs.Client.Fetch(req)
	if err != nil {
		return ""
	}
	return body
}

func (vs *VulnScanner) SendRequest(ctx context.Context, method, rawURL string, body string, headers map[string]string) (*http.Response, string) {
	var reqBody *bytes.Buffer
	if body != "" {
		reqBody = bytes.NewBufferString(body)
	}

	var bodyReader *bytes.Buffer
	if reqBody != nil {
		bodyReader = reqBody
	}

	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, rawURL, nil)
	}
	if err != nil {
		return nil, ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, respBody, err := vs.Client.FetchFull(req)
	if err != nil {
		return nil, ""
	}
	return resp, respBody
}

func Similarity(a, b string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	if len(a) > 2000 {
		a = a[:2000]
	}
	if len(b) > 2000 {
		b = b[:2000]
	}

	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")

	setA := make(map[string]int, len(linesA))
	for _, line := range linesA {
		setA[line]++
	}

	common := 0
	for _, line := range linesB {
		if setA[line] > 0 {
			common++
			setA[line]--
		}
	}

	total := len(linesA) + len(linesB)
	if total == 0 {
		return 1.0
	}
	return float64(2*common) / float64(total)
}

func LogModuleComplete(moduleID string, targetCount, findingCount int, dur time.Duration) {
	slog.Info("[+] 模块检测完成",
		"module", moduleID,
		"targets", targetCount,
		"findings", findingCount,
		"duration", dur,
	)
}
