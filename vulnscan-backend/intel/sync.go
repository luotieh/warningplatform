package intel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

type SyncManager struct {
	sources  []IntelSource
	matcher  *VulnMatcher
	interval time.Duration
	subSvc   *SubscriptionService
}

func NewSyncManager(matcher *VulnMatcher, subSvc *SubscriptionService) *SyncManager {
	return &SyncManager{
		matcher:  matcher,
		interval: 24 * time.Hour,
		sources:  defaultSources(),
		subSvc:   subSvc,
	}
}

func (s *SyncManager) StartSync(ctx context.Context) {
	s.syncOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("[*] 漏洞情报同步已停止")
			return
		case <-ticker.C:
			s.syncOnce(ctx)
		}
	}
}

func (s *SyncManager) syncOnce(ctx context.Context) {
	slog.Info("[*] 开始同步漏洞情报数据...")

	var allNewEntries []CVEEntry

	for i, source := range s.sources {
		if !source.Enabled {
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		entries, err := s.fetchSource(ctx, source)
		if err != nil {
			slog.Warn("同步失败", "source", source.Name, "error", err)
			continue
		}

		s.matcher.LoadCVEs(entries)
		s.sources[i].LastSync = time.Now()
		s.sources[i].EntryCount = len(entries)
		allNewEntries = append(allNewEntries, entries...)

		slog.Info("[+] 数据源同步完成",
			"source", source.Name,
			"entries", len(entries),
		)
	}

	s.syncEPSS(ctx)

	if s.subSvc != nil && len(allNewEntries) > 0 {
		s.subSvc.MatchNewCVEs(allNewEntries)
	}
}

func (s *SyncManager) fetchSource(ctx context.Context, source IntelSource) ([]CVEEntry, error) {
	switch source.Name {
	case "NVD":
		return s.fetchNVD(ctx, source)
	case "CISA KEV":
		return s.fetchCISAKEV(ctx, source)
	case "GitHub Advisory":
		return s.fetchGitHubAdvisory(ctx, source)
	case "CNVD":
		return s.fetchCNVD(ctx, source)
	case "奇安信Ti":
		return s.fetchQiAnXin(ctx, source)
	case "微步在线":
		return s.fetchThreatBook(ctx, source)
	case "绿盟NSFOCUS":
		return s.fetchNSFOCUS(ctx, source)
	default:
		return nil, fmt.Errorf("未实现的数据源: %s", source.Name)
	}
}

var intelHTTPClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 15 * time.Second,
		}).DialContext,
	},
}

func (s *SyncManager) fetchNVD(ctx context.Context, source IntelSource) ([]CVEEntry, error) {
	url := source.URL + "?resultsPerPage=200"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulnScan/1.0")

	resp, err := intelHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取NVD响应失败: %w", err)
	}

	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					V31 []struct {
						Data struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
							VectorString string  `json:"vectorString"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria string `json:"criteria"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
				Published string `json:"published"`
				Modified  string `json:"lastModified"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("解析NVD响应失败: %w", err)
	}

	var entries []CVEEntry
	for _, vuln := range nvdResp.Vulnerabilities {
		cve := vuln.CVE
		entry := CVEEntry{
			ID: cve.ID,
		}

		for _, desc := range cve.Description {
			if desc.Lang == "en" {
				entry.Description = desc.Value
				break
			}
		}

		if len(cve.Metrics.V31) > 0 {
			m := cve.Metrics.V31[0].Data
			entry.CVSSScore = m.BaseScore
			entry.CVSSVector = m.VectorString
			entry.Severity = strings.ToLower(m.BaseSeverity)
		}

		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if strings.HasPrefix(d.Value, "CWE-") {
					entry.CWE = append(entry.CWE, d.Value)
				}
			}
		}

		for _, conf := range cve.Configurations {
			for _, node := range conf.Nodes {
				for _, m := range node.CPEMatch {
					entry.CPE = append(entry.CPE, m.Criteria)
				}
			}
		}

		for _, ref := range cve.References {
			entry.References = append(entry.References, ref.URL)
			urlLower := strings.ToLower(ref.URL)
			if strings.Contains(urlLower, "exploit-db.com") {
				entry.HasExploit = true
				entry.ExploitURLs = append(entry.ExploitURLs, ref.URL)
				if entry.ExploitType == "" {
					entry.ExploitType = "public"
				}
			} else if strings.Contains(urlLower, "packetstorm") || strings.Contains(urlLower, "metasploit") {
				entry.HasExploit = true
				entry.ExploitURLs = append(entry.ExploitURLs, ref.URL)
				entry.ExploitType = "weaponized"
			} else if strings.Contains(urlLower, "github.com") && (strings.Contains(urlLower, "poc") || strings.Contains(urlLower, "exploit") || strings.Contains(urlLower, "cve-")) {
				entry.HasExploit = true
				entry.ExploitURLs = append(entry.ExploitURLs, ref.URL)
				if entry.ExploitType == "" {
					entry.ExploitType = "poc"
				}
			}
		}
		classifyExploit(&entry)

		if pub, err := time.Parse("2006-01-02T15:04:05.000", cve.Published); err == nil {
			entry.Published = pub
		}
		if mod, err := time.Parse("2006-01-02T15:04:05.000", cve.Modified); err == nil {
			entry.Modified = mod
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func (s *SyncManager) fetchCISAKEV(ctx context.Context, source IntelSource) ([]CVEEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulnScan/1.0")

	resp, err := intelHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CISA KEV请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CISA KEV返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取CISA KEV响应失败: %w", err)
	}

	var kevResp struct {
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			ShortDescription  string `json:"shortDescription"`
			DateAdded         string `json:"dateAdded"`
			RequiredAction    string `json:"requiredAction"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &kevResp); err != nil {
		return nil, fmt.Errorf("解析CISA KEV响应失败: %w", err)
	}

	var entries []CVEEntry
	for _, kev := range kevResp.Vulnerabilities {
		entry := CVEEntry{
			ID:          kev.CVEID,
			Description: kev.ShortDescription,
			Severity:    "critical",
			InKEV:       true,
			HasExploit:  true,
		}

		if added, err := time.Parse("2006-01-02", kev.DateAdded); err == nil {
			entry.Published = added
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func (s *SyncManager) fetchGitHubAdvisory(ctx context.Context, source IntelSource) ([]CVEEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL+"?per_page=100", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulnScan/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := intelHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub Advisory请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub Advisory返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取GitHub Advisory响应失败: %w", err)
	}

	var advisories []struct {
		GHSAID      string `json:"ghsa_id"`
		CVEID       string `json:"cve_id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		CVSS        struct {
			Score     float64 `json:"score"`
			VectorStr string  `json:"vector_string"`
		} `json:"cvss"`
		CWEs []struct {
			CWEID string `json:"cwe_id"`
		} `json:"cwes"`
		References  []string `json:"references"`
		PublishedAt string   `json:"published_at"`
		UpdatedAt   string   `json:"updated_at"`
	}

	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil, fmt.Errorf("解析GitHub Advisory响应失败: %w", err)
	}

	var entries []CVEEntry
	for _, adv := range advisories {
		if adv.CVEID == "" {
			continue
		}

		entry := CVEEntry{
			ID:          adv.CVEID,
			Description: adv.Summary,
			Severity:    strings.ToLower(adv.Severity),
			CVSSScore:   adv.CVSS.Score,
			CVSSVector:  adv.CVSS.VectorStr,
			References:  adv.References,
		}

		for _, cwe := range adv.CWEs {
			entry.CWE = append(entry.CWE, cwe.CWEID)
		}

		if pub, err := time.Parse(time.RFC3339, adv.PublishedAt); err == nil {
			entry.Published = pub
		}
		if mod, err := time.Parse(time.RFC3339, adv.UpdatedAt); err == nil {
			entry.Modified = mod
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func classifyExploit(entry *CVEEntry) {
	if !entry.HasExploit {
		return
	}

	if entry.Impact == "" {
		vec := strings.ToLower(entry.CVSSVector)
		switch {
		case strings.Contains(vec, "ac:l") && strings.Contains(vec, "pr:n"):
			entry.Difficulty = "low"
		case strings.Contains(vec, "ac:l"):
			entry.Difficulty = "medium"
		case strings.Contains(vec, "ac:h"):
			entry.Difficulty = "high"
		default:
			entry.Difficulty = "unknown"
		}
	}

	if entry.Impact == "" {
		for _, cwe := range entry.CWE {
			cweLower := strings.ToLower(cwe)
			switch {
			case strings.Contains(cweLower, "cwe-78") || strings.Contains(cweLower, "cwe-94") || strings.Contains(cweLower, "cwe-502"):
				entry.Impact = "rce"
			case strings.Contains(cweLower, "cwe-269") || strings.Contains(cweLower, "cwe-264"):
				entry.Impact = "privilege_escalation"
			case strings.Contains(cweLower, "cwe-400") || strings.Contains(cweLower, "cwe-770"):
				entry.Impact = "dos"
			case strings.Contains(cweLower, "cwe-200") || strings.Contains(cweLower, "cwe-532"):
				entry.Impact = "info_disclosure"
			}
			if entry.Impact != "" {
				break
			}
		}
		if entry.Impact == "" {
			entry.Impact = "other"
		}
	}
}

func (s *SyncManager) GetSources() []IntelSource {
	return s.sources
}

func (s *SyncManager) AddSource(source IntelSource) {
	s.sources = append(s.sources, source)
}

func (s *SyncManager) UpdateSource(name string, fn func(*IntelSource)) bool {
	for i := range s.sources {
		if s.sources[i].Name == name {
			fn(&s.sources[i])
			return true
		}
	}
	return false
}

func (s *SyncManager) DeleteSource(name string) bool {
	for i := range s.sources {
		if s.sources[i].Name == name && s.sources[i].Custom {
			s.sources = append(s.sources[:i], s.sources[i+1:]...)
			return true
		}
	}
	return false
}

func defaultSources() []IntelSource {
	return []IntelSource{
		{
			Name:         "NVD",
			Type:         "cve_database",
			URL:          "https://services.nvd.nist.gov/rest/json/cves/2.0",
			Enabled:      true,
			SyncInterval: "24h",
		},
		{
			Name:         "CISA KEV",
			Type:         "kev",
			URL:          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			Enabled:      true,
			SyncInterval: "12h",
		},
		{
			Name:         "GitHub Advisory",
			Type:         "advisory",
			URL:          "https://api.github.com/advisories",
			Enabled:      true,
			SyncInterval: "24h",
		},
		{
			Name:         "Exploit-DB",
			Type:         "exploit",
			URL:          "https://www.exploit-db.com",
			Enabled:      false,
			SyncInterval: "24h",
		},
		// 国内威胁情报源（需配置 API Key 后手动启用）
		{
			Name:         "CNVD",
			Type:         "cve_database",
			URL:          "https://www.cnvd.org.cn/flaw/list.json",
			Enabled:      false,
			SyncInterval: "12h",
		},
		{
			Name:         "奇安信Ti",
			Type:         "cve_database",
			URL:          "https://ti.qianxin.com/api/v2/vuln/latest",
			Enabled:      false,
			SyncInterval: "12h",
		},
		{
			Name:         "微步在线",
			Type:         "cve_database",
			URL:          "https://api.threatbook.cn/v3/scene/vuln_intelligence",
			Enabled:      false,
			SyncInterval: "12h",
		},
		{
			Name:         "绿盟NSFOCUS",
			Type:         "cve_database",
			URL:          "https://ti.nsfocus.com/api/v1/vuln/list",
			Enabled:      false,
			SyncInterval: "24h",
		},
	}
}
