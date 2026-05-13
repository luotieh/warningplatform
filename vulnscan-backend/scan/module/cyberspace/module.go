package cyberspace

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type CyberSpaceModule struct {
	providers []Provider
}

func NewModule(configs map[string]ProviderConfig) *CyberSpaceModule {
	m := &CyberSpaceModule{}

	if cfg, ok := configs["shodan"]; ok && cfg.Enabled {
		m.providers = append(m.providers, NewShodan(cfg))
	}
	if cfg, ok := configs["fofa"]; ok && cfg.Enabled {
		m.providers = append(m.providers, NewFOFA(cfg))
	}
	if cfg, ok := configs["zoomeye"]; ok && cfg.Enabled {
		m.providers = append(m.providers, NewZoomEye(cfg))
	}
	if cfg, ok := configs["censys"]; ok && cfg.Enabled {
		m.providers = append(m.providers, NewCensys(cfg))
	}

	return m
}

func (m *CyberSpaceModule) ID() string       { return "cyberspace" }
func (m *CyberSpaceModule) Name() string     { return "网络空间测绘" }
func (m *CyberSpaceModule) Category() string { return "recon" }

func (m *CyberSpaceModule) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	if len(m.providers) == 0 {
		slog.Warn("[!] 无可用测绘平台，请配置 API Key")
		return result, nil
	}

	query := parseString(config, "query", "")
	maxResults := parseInt(config, "max_results", 500)
	mode := parseString(config, "mode", "search")

	if query == "" && len(targets) > 0 {
		t := targets[0]
		if t.Host != "" {
			query = t.Host
		} else if t.IP != "" {
			query = t.IP
			mode = "host"
		}
	}

	if query == "" {
		return result, fmt.Errorf("cyberspace: query is required")
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	allAssets := make(map[string]*CyberAsset)

	for _, p := range m.providers {
		wg.Add(1)
		go func(provider Provider) {
			defer wg.Done()

			var assets []*CyberAsset
			var err error

			switch mode {
			case "host":
				assets, err = provider.HostLookup(query)
			default:
				assets, err = provider.Search(query, maxResults/len(m.providers))
			}

			if err != nil {
				slog.Warn("测绘平台查询失败",
					"provider", provider.Name(),
					"query", query,
					"error", err,
				)
				return
			}

			mu.Lock()
			for _, a := range assets {
				key := fmt.Sprintf("%s:%d:%s", a.IP, a.Port, a.Protocol)
				if existing, ok := allAssets[key]; ok {
					mergeAsset(existing, a)
				} else {
					allAssets[key] = a
				}
			}
			mu.Unlock()

			slog.Info("[+] 测绘平台数据采集完成",
				"provider", provider.Name(),
				"assets", len(assets),
			)
		}(p)
	}

	wg.Wait()

	for _, a := range allAssets {
		finding := &core.Finding{
			ModuleID:   m.ID(),
			Type:       "cyber_asset",
			Severity:   "info",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data:       assetToData(a),
		}

		title := fmt.Sprintf("%s:%d", a.IP, a.Port)
		if a.Service != "" {
			title += "/" + a.Service
		}
		if a.Title != "" {
			title += " - " + truncate(a.Title, 40)
		}
		finding.Title = title

		if a.Hostname != "" || len(a.Domains) > 0 {
			finding.Evidence = fmt.Sprintf("host=%s domains=%v org=%s", a.Hostname, a.Domains, a.Org)
		}

		result.Findings = append(result.Findings, finding)
	}

	result.Duration = time.Since(start)
	slog.Info("[+] 网络空间测绘完成",
		"providers", len(m.providers),
		"unique_assets", len(allAssets),
		"duration", result.Duration,
	)

	return result, nil
}

func mergeAsset(existing, incoming *CyberAsset) {
	existing.Source += "," + incoming.Source

	if existing.Service == "" && incoming.Service != "" {
		existing.Service = incoming.Service
	}
	if existing.Version == "" && incoming.Version != "" {
		existing.Version = incoming.Version
	}
	if existing.Banner == "" && incoming.Banner != "" {
		existing.Banner = incoming.Banner
	}
	if existing.OS == "" && incoming.OS != "" {
		existing.OS = incoming.OS
	}
	if existing.Title == "" && incoming.Title != "" {
		existing.Title = incoming.Title
	}
	if existing.Hostname == "" && incoming.Hostname != "" {
		existing.Hostname = incoming.Hostname
	}
	if existing.Cert == nil && incoming.Cert != nil {
		existing.Cert = incoming.Cert
	}

	for _, d := range incoming.Domains {
		found := false
		for _, ed := range existing.Domains {
			if ed == d {
				found = true
				break
			}
		}
		if !found {
			existing.Domains = append(existing.Domains, d)
		}
	}
}

func assetToData(a *CyberAsset) map[string]string {
	data := map[string]string{
		"ip":       a.IP,
		"port":     fmt.Sprintf("%d", a.Port),
		"protocol": a.Protocol,
		"service":  a.Service,
		"version":  a.Version,
		"os":       a.OS,
		"hostname": a.Hostname,
		"country":  a.Country,
		"city":     a.City,
		"org":      a.Org,
		"title":    a.Title,
		"source":   a.Source,
	}
	if len(a.Domains) > 0 {
		data["domains"] = strings.Join(a.Domains, ",")
	}
	if a.Cert != nil {
		data["cert_subject"] = a.Cert.Subject
		data["cert_issuer"] = a.Cert.Issuer
	}
	return data
}

func parseString(config map[string]interface{}, key, def string) string {
	if config != nil {
		if v, ok := config[key].(string); ok {
			return v
		}
	}
	return def
}

func parseInt(config map[string]interface{}, key string, def int) int {
	if config != nil {
		if v, ok := config[key]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return def
}
