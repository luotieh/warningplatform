package analyzer

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WaybackSnapshot struct {
	Timestamp   string `json:"timestamp"`
	OriginalURL string `json:"original_url"`
	ContentHash string `json:"content_hash"`
	Title       string `json:"title"`
	StatusCode  int    `json:"status_code"`
	BodyLength  int    `json:"body_length"`
	Available   bool   `json:"available"`
}

type WaybackVerifyResult struct {
	Available      bool             `json:"available"`
	Snapshot       *WaybackSnapshot `json:"snapshot,omitempty"`
	TitleMatch     bool             `json:"title_match"`
	ContentSimilar bool             `json:"content_similar"`
	SizeDiffRatio  float64          `json:"size_diff_ratio"`
	Suspicious     bool             `json:"suspicious"`
	Reason         string           `json:"reason,omitempty"`
	Error          string           `json:"error,omitempty"`
}

const (
	waybackAPIBase      = "https://archive.org/wayback/available"
	waybackMaxBodyBytes = 2 * 1024 * 1024
	waybackTimeout      = 15 * time.Second
)

func VerifyBaselineViaWayback(ctx context.Context, targetURL string, currentSnap *snapshotData) WaybackVerifyResult {
	ctx, cancel := context.WithTimeout(ctx, waybackTimeout)
	defer cancel()

	snapshot, err := fetchWaybackSnapshot(ctx, targetURL)
	if err != nil {
		return WaybackVerifyResult{Error: err.Error()}
	}
	if snapshot == nil || !snapshot.Available {
		return WaybackVerifyResult{Available: false}
	}

	result := WaybackVerifyResult{
		Available: true,
		Snapshot:  snapshot,
	}

	result.TitleMatch = normalizeTitle(snapshot.Title) == normalizeTitle(currentSnap.Title)

	result.ContentSimilar = snapshot.ContentHash == currentSnap.ContentHash

	if snapshot.BodyLength > 0 && currentSnap.VisibleText != "" {
		currentLen := len(currentSnap.VisibleText)
		diff := absInt(currentLen - snapshot.BodyLength)
		result.SizeDiffRatio = float64(diff) / float64(snapshot.BodyLength)
	}

	if !result.TitleMatch && !result.ContentSimilar && result.SizeDiffRatio > 0.5 {
		result.Suspicious = true
		result.Reason = "与 Wayback Machine 历史快照对比：标题不匹配、内容不一致、页面大小差异超过 50%"
	} else if !result.TitleMatch && result.SizeDiffRatio > 0.8 {
		result.Suspicious = true
		result.Reason = "标题不匹配且页面大小差异超过 80%，可能页面已被大幅篡改"
	}

	return result
}

func fetchWaybackSnapshot(ctx context.Context, targetURL string) (*WaybackSnapshot, error) {
	apiURL := fmt.Sprintf("%s?url=%s&timestamp=20240101", waybackAPIBase, url.QueryEscape(targetURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build wayback request: %w", err)
	}
	req.Header.Set("User-Agent", "VulnScan-Monitor/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback API call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read wayback response: %w", err)
	}

	var apiResp struct {
		ArchivedSnapshots struct {
			Closest *struct {
				Status    string `json:"status"`
				Available bool   `json:"available"`
				URL       string `json:"url"`
				Timestamp string `json:"timestamp"`
			} `json:"closest"`
		} `json:"archived_snapshots"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("parse wayback response: %w", err)
	}

	closest := apiResp.ArchivedSnapshots.Closest
	if closest == nil || !closest.Available {
		return nil, nil
	}

	snapshot := &WaybackSnapshot{
		Timestamp:   closest.Timestamp,
		OriginalURL: targetURL,
		Available:   true,
	}

	archivedContent, err := fetchArchivedPage(ctx, closest.URL)
	if err == nil && archivedContent != nil {
		snapshot.Title = archivedContent.title
		snapshot.ContentHash = archivedContent.contentHash
		snapshot.BodyLength = archivedContent.bodyLength
	}

	return snapshot, nil
}

type archivedPageInfo struct {
	title       string
	contentHash string
	bodyLength  int
}

func fetchArchivedPage(ctx context.Context, archiveURL string) (*archivedPageInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulnScan-Monitor/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, waybackMaxBodyBytes))
	if err != nil {
		return nil, err
	}

	info := &archivedPageInfo{
		bodyLength:  len(body),
		contentHash: fmt.Sprintf("%x", md5.Sum(body)),
	}

	bodyStr := string(body)
	if idx := strings.Index(bodyStr, "<title"); idx >= 0 {
		end := strings.Index(bodyStr[idx:], "</title>")
		if end > 0 {
			tagContent := bodyStr[idx : idx+end]
			if gt := strings.Index(tagContent, ">"); gt >= 0 {
				info.title = strings.TrimSpace(tagContent[gt+1:])
			}
		}
	}

	return info, nil
}

func normalizeTitle(t string) string {
	t = strings.TrimSpace(t)
	t = strings.ToLower(t)
	t = strings.ReplaceAll(t, " ", "")
	t = strings.ReplaceAll(t, "\t", "")
	return t
}
