package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

const epssAPIBase = "https://api.first.org/data/v1/epss"

func (s *SyncManager) syncEPSS(ctx context.Context) {
	cveIDs := make([]string, 0, len(s.matcher.cveDB))
	for id := range s.matcher.cveDB {
		cveIDs = append(cveIDs, id)
	}
	if len(cveIDs) == 0 {
		return
	}

	batchSize := 100
	updated := 0

	for i := 0; i < len(cveIDs); i += batchSize {
		select {
		case <-ctx.Done():
			return
		default:
		}

		end := i + batchSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]

		scores, err := fetchEPSSBatch(ctx, batch)
		if err != nil {
			slog.Warn("EPSS批量查询失败", "batch", i/batchSize, "error", err)
			continue
		}

		for _, score := range scores {
			if entry, ok := s.matcher.cveDB[score.CVE]; ok {
				entry.EPSSScore = score.EPSS
				entry.EPSSPercentile = score.Percentile
				updated++
			}
		}
	}

	if updated > 0 {
		slog.Info("[+] EPSS评分同步完成", "updated", updated)
	}
}

type epssScore struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

func fetchEPSSBatch(ctx context.Context, cveIDs []string) ([]epssScore, error) {
	url := fmt.Sprintf("%s?cve=%s", epssAPIBase, strings.Join(cveIDs, ","))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulnScan/1.0")

	resp, err := intelHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("EPSS API请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取EPSS响应失败: %w", err)
	}

	var epssResp struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &epssResp); err != nil {
		return nil, fmt.Errorf("解析EPSS响应失败: %w", err)
	}

	scores := make([]epssScore, 0, len(epssResp.Data))
	for _, d := range epssResp.Data {
		epss, _ := strconv.ParseFloat(d.EPSS, 64)
		pct, _ := strconv.ParseFloat(d.Percentile, 64)
		scores = append(scores, epssScore{
			CVE:        d.CVE,
			EPSS:       epss,
			Percentile: pct,
		})
	}

	return scores, nil
}
