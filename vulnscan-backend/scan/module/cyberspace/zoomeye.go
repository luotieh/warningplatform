package cyberspace

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

type ZoomEyeProvider struct {
	config ProviderConfig
	client *http.Client
}

func NewZoomEye(cfg ProviderConfig) *ZoomEyeProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.zoomeye.hk"
	}
	return &ZoomEyeProvider{
		config: ProviderConfig{
			APIKey:  cfg.APIKey,
			BaseURL: baseURL,
			Enabled: cfg.Enabled,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (z *ZoomEyeProvider) Name() string { return "zoomeye" }

func (z *ZoomEyeProvider) Search(query string, maxResults int) ([]*CyberAsset, error) {
	if z.config.APIKey == "" {
		return nil, fmt.Errorf("zoomeye: API key not configured")
	}

	var allAssets []*CyberAsset
	page := 1
	perPage := 20

	for len(allAssets) < maxResults {
		apiURL := fmt.Sprintf("%s/host/search?query=%s&page=%d",
			z.config.BaseURL, url.QueryEscape(query), page)

		body, err := z.doGet(apiURL)
		if err != nil {
			slog.Warn("zoomeye search failed", "page", page, "error", err)
			break
		}

		var resp struct {
			Matches []zoomeyeMatch `json:"matches"`
			Total   int            `json:"total"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			break
		}

		for i := range resp.Matches {
			allAssets = append(allAssets, resp.Matches[i].toCyberAsset())
		}

		if len(resp.Matches) < perPage || page*perPage >= resp.Total {
			break
		}
		page++
	}

	if len(allAssets) > maxResults {
		allAssets = allAssets[:maxResults]
	}

	slog.Info("[+] ZoomEye搜索完成", "query", query, "results", len(allAssets))
	return allAssets, nil
}

func (z *ZoomEyeProvider) HostLookup(ip string) ([]*CyberAsset, error) {
	return z.Search(fmt.Sprintf("ip:%s", ip), 100)
}

func (z *ZoomEyeProvider) doGet(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-KEY", z.config.APIKey)

	resp, err := z.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zoomeye: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("zoomeye: read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zoomeye: HTTP %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	return body, nil
}

type zoomeyeMatch struct {
	IP       string `json:"ip"`
	Portinfo struct {
		Port     int    `json:"port"`
		Service  string `json:"service"`
		Product  string `json:"product"`
		Version  string `json:"version"`
		Banner   string `json:"banner"`
		Protocol string `json:"protocol"`
		Title    string `json:"title"`
		OS       string `json:"os"`
	} `json:"portinfo"`
	Geoinfo struct {
		Country struct {
			Code string `json:"code"`
		} `json:"country"`
		City struct {
			Name string `json:"names"`
		} `json:"city"`
		ASN int    `json:"asn"`
		Org string `json:"organization"`
	} `json:"geoinfo"`
	Rdns     string   `json:"rdns"`
	Hostname []string `json:"hostname"`
	SSL      *struct {
		Cert struct {
			Subject struct {
				CN string `json:"CN"`
			} `json:"subject"`
			Issuer struct {
				CN string `json:"CN"`
			} `json:"issuer"`
			Validity struct {
				End string `json:"end"`
			} `json:"validity"`
			Extensions struct {
				SANs []string `json:"subjectAltName"`
			} `json:"extensions"`
		} `json:"cert"`
	} `json:"ssl"`
}

func (m *zoomeyeMatch) toCyberAsset() *CyberAsset {
	a := &CyberAsset{
		IP:       m.IP,
		Port:     m.Portinfo.Port,
		Protocol: m.Portinfo.Protocol,
		Service:  m.Portinfo.Product,
		Version:  m.Portinfo.Version,
		Banner:   truncate(m.Portinfo.Banner, 512),
		OS:       m.Portinfo.OS,
		Title:    m.Portinfo.Title,
		Country:  m.Geoinfo.Country.Code,
		City:     m.Geoinfo.City.Name,
		ASN:      m.Geoinfo.ASN,
		Org:      m.Geoinfo.Org,
		Source:   "zoomeye",
		LastSeen: time.Now(),
	}

	if len(m.Hostname) > 0 {
		a.Hostname = m.Hostname[0]
		a.Domains = m.Hostname
	} else if m.Rdns != "" {
		a.Hostname = m.Rdns
	}

	if m.SSL != nil {
		a.Cert = &CertInfo{
			Subject:  m.SSL.Cert.Subject.CN,
			Issuer:   m.SSL.Cert.Issuer.CN,
			NotAfter: m.SSL.Cert.Validity.End,
			SANs:     m.SSL.Cert.Extensions.SANs,
		}
	}

	return a
}
