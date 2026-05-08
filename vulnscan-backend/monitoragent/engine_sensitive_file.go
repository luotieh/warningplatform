package monitoragent

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type SensitiveFileEngine struct {
	Rules RuleStore
}

func (e *SensitiveFileEngine) Name() string { return "sensitive_file" }

func (e *SensitiveFileEngine) Run(ctx context.Context, task *TaskMessage, snap *PageSnapshot) (map[string]any, error) {
	result := map[string]any{
		"url":     task.URL,
		"has_hit": false,
	}

	paths := e.loadFilePaths()
	if len(paths) == 0 {
		result["skipped"] = true
		result["reason"] = "no file paths configured in rule store"
		return result, nil
	}

	baseURL := strings.TrimRight(task.URL, "/")
	client := &http.Client{Timeout: 10 * time.Second}

	soft404Size, soft404Hash := e.detectSoft404Baseline(ctx, client, baseURL)

	var findings []map[string]any
	semaphore := make(chan struct{}, 10)

	type probeResult struct {
		path   string
		status int
		size   int
		body   string
	}

	results := make(chan probeResult, len(paths))

	for _, p := range paths {
		select {
		case <-ctx.Done():
			break
		case semaphore <- struct{}{}:
		}

		go func(path string) {
			defer func() { <-semaphore }()

			url := baseURL + "/" + strings.TrimLeft(path, "/")
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; MonitorBot/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			size := len(body)
			if resp.ContentLength > 0 {
				size = int(resp.ContentLength)
			}

			results <- probeResult{path: path, status: resp.StatusCode, size: size, body: string(body)}
		}(p)
	}

	go func() {
		for i := 0; i < cap(semaphore); i++ {
			semaphore <- struct{}{}
		}
		close(results)
	}()

	var rawFindings []probeResult
	for r := range results {
		if r.status == 200 && r.size > 0 {
			rawFindings = append(rawFindings, r)
		}
	}

	sizeCount := map[int]int{}
	for _, f := range rawFindings {
		sizeCount[f.size]++
	}

	for _, f := range rawFindings {
		isSoft404 := false
		reason := ""

		if soft404Size > 0 && abs(f.size-soft404Size) <= 10 {
			isSoft404 = true
			reason = "响应大小与随机路径基线一致"
		}
		if soft404Hash != "" && simpleHash(f.body) == soft404Hash {
			isSoft404 = true
			reason = "响应内容与随机路径基线一致"
		}
		if !isSoft404 && sizeCount[f.size] >= 3 && len(rawFindings) > 3 {
			isSoft404 = true
			reason = fmt.Sprintf("有 %d 个文件大小均为 %d B，疑似统一错误页", sizeCount[f.size], f.size)
		}
		if !isSoft404 && e.isSoft404Content(f.body) {
			isSoft404 = true
			reason = "响应内容包含错误页面特征"
		}

		finding := map[string]any{
			"path":   f.path,
			"url":    fmt.Sprintf("%s/%s", baseURL, strings.TrimLeft(f.path, "/")),
			"status": f.status,
			"size":   f.size,
		}
		if isSoft404 {
			finding["soft_404"] = true
			finding["soft_404_reason"] = reason
		}
		findings = append(findings, finding)
	}

	realFindings := 0
	for _, f := range findings {
		if sf, _ := f["soft_404"].(bool); !sf {
			realFindings++
		}
	}

	result["findings"] = findings
	result["total_probed"] = len(paths)
	result["soft_404_baseline_size"] = soft404Size

	if realFindings > 0 {
		result["has_hit"] = true
	}

	return result, nil
}

func (e *SensitiveFileEngine) detectSoft404Baseline(ctx context.Context, client *http.Client, baseURL string) (int, string) {
	randomPaths := []string{
		"this-page-does-not-exist-" + fmt.Sprintf("%d", time.Now().UnixNano()%999999) + ".html",
		"random-check-" + fmt.Sprintf("%d", time.Now().UnixNano()%888888) + ".php",
	}

	var sizes []int
	var hashes []string
	for _, p := range randomPaths {
		url := baseURL + "/" + p
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; MonitorBot/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == 200 {
			sizes = append(sizes, len(body))
			hashes = append(hashes, simpleHash(string(body)))
		}
	}

	if len(sizes) >= 2 && abs(sizes[0]-sizes[1]) <= 10 {
		return sizes[0], hashes[0]
	}
	if len(sizes) == 1 {
		return sizes[0], hashes[0]
	}
	return 0, ""
}

func simpleHash(content string) string {
	content = strings.TrimSpace(content)
	if len(content) > 2048 {
		content = content[:2048]
	}
	return fmt.Sprintf("%x", md5.Sum([]byte(content)))
}

func (e *SensitiveFileEngine) isSoft404Content(body string) bool {
	patterns := e.loadSoft404Patterns()
	if len(patterns) == 0 {
		return false
	}
	lower := strings.ToLower(body)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func (e *SensitiveFileEngine) loadSoft404Patterns() []string {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("sf_engine")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		Soft404Patterns []struct {
			Pattern string `json:"pattern"`
		} `json:"soft_404_patterns"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	patterns := make([]string, 0, len(cfg.Soft404Patterns))
	for _, p := range cfg.Soft404Patterns {
		if p.Pattern != "" {
			patterns = append(patterns, p.Pattern)
		}
	}
	return patterns
}

func (e *SensitiveFileEngine) loadFilePaths() []string {
	if e.Rules == nil {
		return nil
	}

	allRules, err := e.Rules.GetAllRules()
	if err != nil {
		return nil
	}

	var paths []string
	for key, data := range allRules {
		if !strings.HasPrefix(key, "lib/file/") {
			continue
		}
		var lib struct {
			Entries []struct {
				Path string `json:"path"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(data, &lib); err != nil {
			continue
		}
		for _, entry := range lib.Entries {
			if entry.Path != "" {
				paths = append(paths, entry.Path)
			}
		}
	}

	return paths
}
