package engine

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type VulnScanner struct {
	Client      *ScanHTTPClient
	Concurrency int
	pool        *ClientPool
	poolKey     string
}

func NewVulnScanner(config map[string]interface{}, moduleOpts ...ClientOption) *VulnScanner {
	concurrency := GetConfigInt(config, "concurrency", 10)

	pool := GetGlobalClientPool()
	poolKey := ""
	if name, ok := config["module_name"].(string); ok {
		poolKey = name
	}

	var client *ScanHTTPClient
	if len(moduleOpts) > 0 || poolKey != "" {
		opts := append(ClientFromConfig(config), moduleOpts...)
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

type TargetTestFunc func(ctx context.Context, target *Target) []*Finding

func (vs *VulnScanner) RunTargets(ctx context.Context, moduleID string, targets []*Target, testFn TargetTestFunc) *ModuleResult {
	start := time.Now()
	result := &ModuleResult{ModuleID: moduleID}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, vs.Concurrency)

	for _, t := range targets {
		if t.URL == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *Target) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := testFn(ctx, target)
			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				mu.Unlock()
			}
		}(t)
	}

	wg.Wait()
	result.Duration = time.Since(start)
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

func (vs *VulnScanner) SendInjected(ctx context.Context, target *Target, point InjectionPoint, payload string) (string, int, error) {
	req, err := BuildInjectedRequest(ctx, target, point, payload)
	if err != nil {
		return "", 0, err
	}
	return vs.Client.Fetch(req)
}

func (vs *VulnScanner) SendInjectedFull(ctx context.Context, target *Target, point InjectionPoint, payload string) (*http.Response, string, error) {
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

	la := min(len(a), 2000)
	lb := min(len(b), 2000)
	a = a[:la]
	b = b[:lb]

	common := 0
	setA := make(map[string]int)
	for i := 0; i < len(a); {
		j := i
		for j < len(a) && a[j] != '\n' {
			j++
		}
		line := a[i:j]
		setA[line]++
		i = j + 1
	}

	for i := 0; i < len(b); {
		j := i
		for j < len(b) && b[j] != '\n' {
			j++
		}
		line := b[i:j]
		if setA[line] > 0 {
			common++
			setA[line]--
		}
		i = j + 1
	}

	lineCountA := 0
	for i := 0; i < len(a); {
		j := i
		for j < len(a) && a[j] != '\n' {
			j++
		}
		lineCountA++
		i = j + 1
	}

	lineCountB := 0
	for i := 0; i < len(b); {
		j := i
		for j < len(b) && b[j] != '\n' {
			j++
		}
		lineCountB++
		i = j + 1
	}

	total := lineCountA + lineCountB
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
