package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (s *SyncManager) fetchCNVD(ctx context.Context, source IntelSource) ([]CVEEntry, error) {
	url := source.URL
	if !strings.Contains(url, "/api") {
		url = "https://www.cnvd.org.cn/flaw/list.json?max=100"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; VulnScan/1.0)")
	req.Header.Set("Accept", "application/json")
	if source.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+source.APIKey)
	}

	resp, err := intelHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CNVD请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CNVD返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取CNVD响应失败: %w", err)
	}

	var cnvdResp struct {
		Data struct {
			Records []struct {
				CNVDID      string `json:"cnvdId"`
				CVEID       string `json:"cveId"`
				Title       string `json:"title"`
				Severity    string `json:"hazardLevel"`
				PublishTime string `json:"publishTime"`
				Product     string `json:"product"`
				Description string `json:"description"`
			} `json:"records"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &cnvdResp); err != nil {
		return nil, fmt.Errorf("解析CNVD响应失败: %w", err)
	}

	var entries []CVEEntry
	for _, r := range cnvdResp.Data.Records {
		id := r.CVEID
		if id == "" {
			id = r.CNVDID
		}
		if id == "" {
			continue
		}

		severity := mapCNVDSeverity(r.Severity)
		entry := CVEEntry{
			ID:          id,
			Description: r.Title,
			Severity:    severity,
		}
		if r.Description != "" {
			entry.Description = r.Description
		}
		if pub, err := time.Parse("2006-01-02", r.PublishTime); err == nil {
			entry.Published = pub
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func (s *SyncManager) fetchQiAnXin(ctx context.Context, source IntelSource) ([]CVEEntry, error) {
	url := source.URL
	if url == "" {
		url = "https://ti.qianxin.com/api/v2/vuln/latest"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"?limit=100", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulnScan/1.0")
	req.Header.Set("Accept", "application/json")
	if source.APIKey != "" {
		req.Header.Set("X-API-Key", source.APIKey)
	}

	resp, err := intelHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("奇安信Ti请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("奇安信Ti返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取奇安信Ti响应失败: %w", err)
	}

	var qaxResp struct {
		Data []struct {
			CVEID       string  `json:"cve_id"`
			Title       string  `json:"title"`
			Description string  `json:"description"`
			Severity    string  `json:"severity"`
			CVSSScore   float64 `json:"cvss_score"`
			PublishDate string  `json:"publish_date"`
			HasExploit  bool    `json:"has_exploit"`
			Products    []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"affected_products"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &qaxResp); err != nil {
		return nil, fmt.Errorf("解析奇安信Ti响应失败: %w", err)
	}

	var entries []CVEEntry
	for _, v := range qaxResp.Data {
		if v.CVEID == "" {
			continue
		}
		entry := CVEEntry{
			ID:          v.CVEID,
			Description: v.Description,
			Severity:    strings.ToLower(v.Severity),
			CVSSScore:   v.CVSSScore,
			HasExploit:  v.HasExploit,
		}
		if entry.Description == "" {
			entry.Description = v.Title
		}
		if pub, err := time.Parse("2006-01-02", v.PublishDate); err == nil {
			entry.Published = pub
		}
		classifyExploit(&entry)
		entries = append(entries, entry)
	}

	return entries, nil
}

func (s *SyncManager) fetchThreatBook(ctx context.Context, source IntelSource) ([]CVEEntry, error) {
	url := source.URL
	if url == "" {
		url = "https://api.threatbook.cn/v3/scene/vuln_intelligence"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"?limit=50", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulnScan/1.0")
	if source.APIKey != "" {
		req.Header.Set("apikey", source.APIKey)
	}

	resp, err := intelHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("微步在线请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("微步在线返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取微步在线响应失败: %w", err)
	}

	var tbResp struct {
		Data struct {
			List []struct {
				CVEID       string   `json:"cve_id"`
				Title       string   `json:"vuln_name"`
				Severity    string   `json:"severity"`
				Score       float64  `json:"cvss_score"`
				Description string   `json:"description"`
				PublishTime string   `json:"publish_time"`
				HasPOC      bool     `json:"has_poc"`
				Tags        []string `json:"tags"`
			} `json:"list"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &tbResp); err != nil {
		return nil, fmt.Errorf("解析微步在线响应失败: %w", err)
	}

	var entries []CVEEntry
	for _, v := range tbResp.Data.List {
		if v.CVEID == "" {
			continue
		}
		entry := CVEEntry{
			ID:          v.CVEID,
			Description: v.Description,
			Severity:    strings.ToLower(v.Severity),
			CVSSScore:   v.Score,
			HasExploit:  v.HasPOC,
		}
		if entry.Description == "" {
			entry.Description = v.Title
		}
		if pub, err := time.Parse("2006-01-02", v.PublishTime); err == nil {
			entry.Published = pub
		}
		if v.HasPOC {
			entry.ExploitType = "poc"
		}
		classifyExploit(&entry)
		entries = append(entries, entry)
	}

	return entries, nil
}

func (s *SyncManager) fetchNSFOCUS(ctx context.Context, source IntelSource) ([]CVEEntry, error) {
	url := source.URL
	if url == "" {
		url = "https://ti.nsfocus.com/api/v1/vuln/list"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"?page_size=100", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulnScan/1.0")
	if source.APIKey != "" {
		req.Header.Set("X-API-Token", source.APIKey)
	}

	resp, err := intelHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("绿盟Ti请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("绿盟Ti返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取绿盟Ti响应失败: %w", err)
	}

	var nsfResp struct {
		Data []struct {
			CVEID       string  `json:"cve_id"`
			Title       string  `json:"title"`
			Severity    string  `json:"severity"`
			CVSSScore   float64 `json:"cvss_score"`
			Description string  `json:"description"`
			PublishDate string  `json:"publish_date"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &nsfResp); err != nil {
		return nil, fmt.Errorf("解析绿盟Ti响应失败: %w", err)
	}

	var entries []CVEEntry
	for _, v := range nsfResp.Data {
		if v.CVEID == "" {
			continue
		}
		entry := CVEEntry{
			ID:          v.CVEID,
			Description: v.Description,
			Severity:    strings.ToLower(v.Severity),
			CVSSScore:   v.CVSSScore,
		}
		if entry.Description == "" {
			entry.Description = v.Title
		}
		if pub, err := time.Parse("2006-01-02", v.PublishDate); err == nil {
			entry.Published = pub
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func mapCNVDSeverity(level string) string {
	switch strings.ToLower(level) {
	case "超危", "high":
		return "critical"
	case "高危":
		return "high"
	case "中危", "medium":
		return "medium"
	case "低危", "low":
		return "low"
	default:
		return "medium"
	}
}
