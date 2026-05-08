package cyberspace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type CensysProvider struct {
	config ProviderConfig
	client *http.Client
}

func NewCensys(cfg ProviderConfig) *CensysProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://search.censys.io/api"
	}
	return &CensysProvider{
		config: ProviderConfig{
			APIKey:    cfg.APIKey,
			APISecret: cfg.APISecret,
			BaseURL:   baseURL,
			Enabled:   cfg.Enabled,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CensysProvider) Name() string { return "censys" }

func (c *CensysProvider) Search(query string, maxResults int) ([]*CyberAsset, error) {
	if c.config.APIKey == "" || c.config.APISecret == "" {
		return nil, fmt.Errorf("censys: API ID or Secret not configured")
	}

	var allAssets []*CyberAsset
	cursor := ""
	perPage := 100

	for len(allAssets) < maxResults {
		reqBody := map[string]interface{}{
			"q":        query,
			"per_page": perPage,
		}
		if cursor != "" {
			reqBody["cursor"] = cursor
		}

		bodyBytes, _ := json.Marshal(reqBody)
		apiURL := fmt.Sprintf("%s/v2/hosts/search", c.config.BaseURL)

		req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return allAssets, err
		}
		req.SetBasicAuth(c.config.APIKey, c.config.APISecret)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			slog.Warn("censys search failed", "error", err)
			break
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return allAssets, fmt.Errorf("censys: HTTP %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
		}

		var result struct {
			Result struct {
				Hits  []censysHit `json:"hits"`
				Links struct {
					Next string `json:"next"`
				} `json:"links"`
				Total int `json:"total"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			break
		}

		for i := range result.Result.Hits {
			assets := result.Result.Hits[i].toCyberAssets()
			allAssets = append(allAssets, assets...)
		}

		cursor = result.Result.Links.Next
		if cursor == "" || len(result.Result.Hits) < perPage {
			break
		}
	}

	if len(allAssets) > maxResults {
		allAssets = allAssets[:maxResults]
	}

	slog.Info("[+] Censys搜索完成", "query", query, "results", len(allAssets))
	return allAssets, nil
}

func (c *CensysProvider) HostLookup(ip string) ([]*CyberAsset, error) {
	if c.config.APIKey == "" || c.config.APISecret == "" {
		return nil, fmt.Errorf("censys: API ID or Secret not configured")
	}

	apiURL := fmt.Sprintf("%s/v2/hosts/%s", c.config.BaseURL, ip)

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.config.APIKey, c.config.APISecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("censys: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("censys: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Result censysHit `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Result.toCyberAssets(), nil
}

type censysHit struct {
	IP       string `json:"ip"`
	Services []struct {
		Port              int    `json:"port"`
		ServiceName       string `json:"service_name"`
		TransportProtocol string `json:"transport_protocol"`
		Software          []struct {
			Product string `json:"product"`
			Version string `json:"version"`
		} `json:"software"`
		Banner string `json:"banner"`
		TLS    *struct {
			Certificates struct {
				Leaf struct {
					Names       []string `json:"names"`
					SubjectDN   string   `json:"subject_dn"`
					IssuerDN    string   `json:"issuer_dn"`
					ValidityEnd string   `json:"validity_end"`
				} `json:"leaf"`
			} `json:"certificates"`
		} `json:"tls"`
		HTTP *struct {
			Response struct {
				HTMLTitle string `json:"html_title"`
			} `json:"response"`
		} `json:"http"`
	} `json:"services"`
	Location struct {
		Country     string `json:"country"`
		City        string `json:"city"`
		CountryCode string `json:"country_code"`
	} `json:"location"`
	AutonomousSystem struct {
		ASN  int    `json:"asn"`
		Name string `json:"name"`
	} `json:"autonomous_system"`
	OperatingSystem struct {
		Product string `json:"product"`
		Version string `json:"version"`
	} `json:"operating_system"`
	DNS struct {
		Names   []string `json:"names"`
		Reverse []string `json:"reverse_dns"`
	} `json:"dns"`
}

func (h *censysHit) toCyberAssets() []*CyberAsset {
	var assets []*CyberAsset

	for _, svc := range h.Services {
		a := &CyberAsset{
			IP:       h.IP,
			Port:     svc.Port,
			Protocol: svc.TransportProtocol,
			Service:  svc.ServiceName,
			Banner:   truncate(svc.Banner, 512),
			Country:  h.Location.CountryCode,
			City:     h.Location.City,
			ASN:      h.AutonomousSystem.ASN,
			Org:      h.AutonomousSystem.Name,
			Source:   "censys",
			LastSeen: time.Now(),
		}

		if h.OperatingSystem.Product != "" {
			a.OS = h.OperatingSystem.Product
			if h.OperatingSystem.Version != "" {
				a.OS += " " + h.OperatingSystem.Version
			}
		}

		if len(svc.Software) > 0 {
			a.Service = svc.Software[0].Product
			a.Version = svc.Software[0].Version
		}

		if len(h.DNS.Names) > 0 {
			a.Domains = h.DNS.Names
			a.Hostname = h.DNS.Names[0]
		} else if len(h.DNS.Reverse) > 0 {
			a.Hostname = h.DNS.Reverse[0]
		}

		if svc.HTTP != nil {
			a.Title = svc.HTTP.Response.HTMLTitle
		}

		if svc.TLS != nil {
			leaf := svc.TLS.Certificates.Leaf
			a.Cert = &CertInfo{
				Subject:  leaf.SubjectDN,
				Issuer:   leaf.IssuerDN,
				SANs:     leaf.Names,
				NotAfter: leaf.ValidityEnd,
			}
		}

		assets = append(assets, a)
	}

	if len(assets) == 0 {
		assets = append(assets, &CyberAsset{
			IP:      h.IP,
			Country: h.Location.CountryCode,
			City:    h.Location.City,
			ASN:     h.AutonomousSystem.ASN,
			Org:     h.AutonomousSystem.Name,
			Source:  "censys",
		})
	}

	return assets
}
