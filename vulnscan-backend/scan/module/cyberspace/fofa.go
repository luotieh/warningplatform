package cyberspace

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type FOFAProvider struct {
	config ProviderConfig
	client *http.Client
}

func NewFOFA(cfg ProviderConfig) *FOFAProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://fofa.info"
	}
	return &FOFAProvider{
		config: ProviderConfig{
			APIKey:    cfg.APIKey,
			APISecret: cfg.APISecret,
			BaseURL:   baseURL,
			Enabled:   cfg.Enabled,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *FOFAProvider) Name() string { return "fofa" }

func (f *FOFAProvider) Search(query string, maxResults int) ([]*CyberAsset, error) {
	if f.config.APIKey == "" || f.config.APISecret == "" {
		return nil, fmt.Errorf("fofa: email or API key not configured")
	}

	qbase64 := base64.StdEncoding.EncodeToString([]byte(query))
	fields := "ip,port,protocol,host,domain,title,server,banner,os,country,city,as_number,as_organization,cert"

	size := maxResults
	if size > 10000 {
		size = 10000
	}

	apiURL := fmt.Sprintf("%s/api/v1/search/all?email=%s&key=%s&qbase64=%s&fields=%s&size=%d",
		f.config.BaseURL,
		url.QueryEscape(f.config.APIKey),
		url.QueryEscape(f.config.APISecret),
		url.QueryEscape(qbase64),
		url.QueryEscape(fields),
		size,
	)

	resp, err := f.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("fofa: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("fofa: read failed: %w", err)
	}

	var result struct {
		Error   bool       `json:"error"`
		ErrMsg  string     `json:"errmsg"`
		Results [][]string `json:"results"`
		Size    int        `json:"size"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fofa: parse error: %w", err)
	}

	if result.Error {
		return nil, fmt.Errorf("fofa: API error: %s", result.ErrMsg)
	}

	var assets []*CyberAsset
	for _, row := range result.Results {
		if len(row) < 14 {
			continue
		}

		port, _ := strconv.Atoi(row[1])
		asn, _ := strconv.Atoi(row[11])

		a := &CyberAsset{
			IP:       row[0],
			Port:     port,
			Protocol: row[2],
			Hostname: row[3],
			Title:    row[5],
			Service:  row[6],
			Banner:   truncate(row[7], 512),
			OS:       row[8],
			Country:  row[9],
			City:     row[10],
			ASN:      asn,
			Org:      row[12],
			Source:   "fofa",
			LastSeen: time.Now(),
		}

		if row[4] != "" {
			a.Domains = []string{row[4]}
		}

		if row[13] != "" {
			a.Cert = parseFOFACert(row[13])
		}

		assets = append(assets, a)
	}

	slog.Info("[+] FOFA搜索完成", "query", query, "results", len(assets))
	return assets, nil
}

func (f *FOFAProvider) HostLookup(ip string) ([]*CyberAsset, error) {
	return f.Search(fmt.Sprintf(`ip="%s"`, ip), 100)
}

func parseFOFACert(certStr string) *CertInfo {
	if certStr == "" {
		return nil
	}

	ci := &CertInfo{}
	parts := strings.Split(certStr, "\n")
	for _, line := range parts {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Subject:") {
			ci.Subject = strings.TrimPrefix(line, "Subject:")
			ci.Subject = strings.TrimSpace(ci.Subject)
		} else if strings.HasPrefix(line, "Issuer:") {
			ci.Issuer = strings.TrimPrefix(line, "Issuer:")
			ci.Issuer = strings.TrimSpace(ci.Issuer)
		}
	}

	return ci
}
