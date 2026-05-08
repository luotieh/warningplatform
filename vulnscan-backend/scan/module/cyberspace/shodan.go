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

type ShodanProvider struct {
	config ProviderConfig
	client *http.Client
}

func NewShodan(cfg ProviderConfig) *ShodanProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.shodan.io"
	}
	return &ShodanProvider{
		config: ProviderConfig{
			APIKey:  cfg.APIKey,
			BaseURL: baseURL,
			Enabled: cfg.Enabled,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *ShodanProvider) Name() string { return "shodan" }

func (s *ShodanProvider) Search(query string, maxResults int) ([]*CyberAsset, error) {
	if s.config.APIKey == "" {
		return nil, fmt.Errorf("shodan: API key not configured")
	}

	var allAssets []*CyberAsset
	page := 1
	perPage := 100

	for len(allAssets) < maxResults {
		apiURL := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s&page=%d",
			s.config.BaseURL, s.config.APIKey, url.QueryEscape(query), page)

		body, err := s.doGet(apiURL)
		if err != nil {
			slog.Warn("shodan search failed", "page", page, "error", err)
			break
		}

		var resp struct {
			Matches []shodanMatch `json:"matches"`
			Total   int           `json:"total"`
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

	return allAssets, nil
}

func (s *ShodanProvider) HostLookup(ip string) ([]*CyberAsset, error) {
	if s.config.APIKey == "" {
		return nil, fmt.Errorf("shodan: API key not configured")
	}

	apiURL := fmt.Sprintf("%s/shodan/host/%s?key=%s",
		s.config.BaseURL, url.PathEscape(ip), s.config.APIKey)

	body, err := s.doGet(apiURL)
	if err != nil {
		return nil, err
	}

	var resp struct {
		IP       string        `json:"ip_str"`
		OS       string        `json:"os"`
		Org      string        `json:"org"`
		ISP      string        `json:"isp"`
		ASN      string        `json:"asn"`
		Country  string        `json:"country_code"`
		City     string        `json:"city"`
		Hostname []string      `json:"hostnames"`
		Domains  []string      `json:"domains"`
		Ports    []int         `json:"ports"`
		Data     []shodanMatch `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("shodan: parse error: %w", err)
	}

	var assets []*CyberAsset
	for i := range resp.Data {
		a := resp.Data[i].toCyberAsset()
		a.OS = resp.OS
		a.Org = resp.Org
		a.ISP = resp.ISP
		a.Country = resp.Country
		a.City = resp.City
		a.Domains = resp.Domains
		if len(resp.Hostname) > 0 {
			a.Hostname = resp.Hostname[0]
		}
		assets = append(assets, a)
	}

	return assets, nil
}

func (s *ShodanProvider) doGet(rawURL string) ([]byte, error) {
	resp, err := s.client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("shodan: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("shodan: read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan: HTTP %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	return body, nil
}

type shodanMatch struct {
	IP        interface{} `json:"ip"`
	IPStr     string      `json:"ip_str"`
	Port      int         `json:"port"`
	Transport string      `json:"transport"`
	Product   string      `json:"product"`
	Version   string      `json:"version"`
	Data      string      `json:"data"`
	OS        string      `json:"os"`
	Org       string      `json:"org"`
	ISP       string      `json:"isp"`
	ASN       string      `json:"asn"`
	Country   string      `json:"country_code"`
	City      string      `json:"city"`
	Hostname  []string    `json:"hostnames"`
	Domains   []string    `json:"domains"`
	HTTP      *struct {
		Title string `json:"title"`
	} `json:"http,omitempty"`
	SSL *struct {
		Cert struct {
			Subject struct {
				CN string `json:"CN"`
			} `json:"subject"`
			Issuer struct {
				CN string `json:"CN"`
			} `json:"issuer"`
			Expires string `json:"expires"`
		} `json:"cert"`
	} `json:"ssl,omitempty"`
}

func (m *shodanMatch) toCyberAsset() *CyberAsset {
	a := &CyberAsset{
		IP:       m.IPStr,
		Port:     m.Port,
		Protocol: m.Transport,
		Service:  m.Product,
		Version:  m.Version,
		Banner:   truncate(m.Data, 512),
		OS:       m.OS,
		Org:      m.Org,
		ISP:      m.ISP,
		Country:  m.Country,
		City:     m.City,
		Domains:  m.Domains,
		Source:   "shodan",
		LastSeen: time.Now(),
	}

	if len(m.Hostname) > 0 {
		a.Hostname = m.Hostname[0]
	}

	if m.HTTP != nil {
		a.Title = m.HTTP.Title
	}

	if m.SSL != nil {
		a.Cert = &CertInfo{
			Subject:  m.SSL.Cert.Subject.CN,
			Issuer:   m.SSL.Cert.Issuer.CN,
			NotAfter: m.SSL.Cert.Expires,
		}
	}

	return a
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
