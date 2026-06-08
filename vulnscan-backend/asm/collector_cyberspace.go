package asm

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"code.yt-security.com/public/scanengine/module/cyberspace"
)

type CyberspaceCollector struct {
	providers map[string]cyberspace.Provider
}

func NewCyberspaceCollector(configs map[string]cyberspace.ProviderConfig) *CyberspaceCollector {
	c := &CyberspaceCollector{
		providers: make(map[string]cyberspace.Provider),
	}
	if cfg, ok := configs["fofa"]; ok && cfg.Enabled {
		c.providers["fofa"] = cyberspace.NewFOFA(cfg)
	}
	if cfg, ok := configs["shodan"]; ok && cfg.Enabled {
		c.providers["shodan"] = cyberspace.NewShodan(cfg)
	}
	if cfg, ok := configs["zoomeye"]; ok && cfg.Enabled {
		c.providers["zoomeye"] = cyberspace.NewZoomEye(cfg)
	}
	if cfg, ok := configs["censys"]; ok && cfg.Enabled {
		c.providers["censys"] = cyberspace.NewCensys(cfg)
	}
	return c
}

func (c *CyberspaceCollector) Name() string { return "cyberspace" }

func (c *CyberspaceCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	if len(c.providers) == 0 {
		return nil, nil
	}

	query := buildCyberspaceQuery(seed)
	if query == "" {
		return nil, nil
	}

	var allAssets []DiscoveredAsset

	for name, provider := range c.providers {
		select {
		case <-ctx.Done():
			return allAssets, ctx.Err()
		default:
		}

		results, err := provider.Search(query, 200)
		if err != nil {
			slog.Warn("ASM cyberspace 收集器查询失败",
				"provider", name, "query", query, "error", err)
			continue
		}

		for _, ca := range results {
			assets := cyberAssetToDiscovered(ca, name, seed.Value)
			allAssets = append(allAssets, assets...)
		}

		slog.Info("[+] ASM cyberspace 收集完成",
			"provider", name, "query", query, "results", len(results))
	}

	return allAssets, nil
}

func buildCyberspaceQuery(seed Seed) string {
	switch seed.Type {
	case "domain":
		return fmt.Sprintf("domain=\"%s\"", seed.Value)
	case "ip":
		if strings.Contains(seed.Value, "/") {
			return fmt.Sprintf("ip=\"%s\"", seed.Value)
		}
		return fmt.Sprintf("ip=\"%s\"", seed.Value)
	case "asn":
		return fmt.Sprintf("asn=\"%s\"", seed.Value)
	case "keyword":
		return seed.Value
	default:
		return ""
	}
}

func cyberAssetToDiscovered(ca *cyberspace.CyberAsset, source string, seedValue string) []DiscoveredAsset {
	var assets []DiscoveredAsset
	now := time.Now()

	if ca.IP != "" {
		attrs := map[string]string{
			"source_provider": source,
			"seed":            seedValue,
		}
		if ca.Port > 0 {
			attrs["port"] = strconv.Itoa(ca.Port)
		}
		if ca.Service != "" {
			attrs["service"] = ca.Service
		}
		if ca.OS != "" {
			attrs["os"] = ca.OS
		}
		if ca.Country != "" {
			attrs["country"] = ca.Country
		}
		if ca.Org != "" {
			attrs["org"] = ca.Org
		}
		if ca.Title != "" {
			attrs["title"] = ca.Title
		}
		if ca.Banner != "" && len(ca.Banner) < 200 {
			attrs["banner"] = ca.Banner
		}

		assets = append(assets, DiscoveredAsset{
			Type:       "ip",
			Value:      ca.IP,
			Source:     "cyberspace-" + source,
			Attributes: attrs,
			FirstSeen:  now,
			LastSeen:   now,
			Status:     "active",
		})
	}

	for _, domain := range ca.Domains {
		if domain == "" {
			continue
		}
		assets = append(assets, DiscoveredAsset{
			Type:   "domain",
			Value:  domain,
			Source: "cyberspace-" + source,
			Attributes: map[string]string{
				"ip":              ca.IP,
				"source_provider": source,
				"seed":            seedValue,
			},
			FirstSeen: now,
			LastSeen:  now,
			Status:    "active",
		})
	}

	if ca.Hostname != "" && ca.Hostname != ca.IP {
		assets = append(assets, DiscoveredAsset{
			Type:   "domain",
			Value:  ca.Hostname,
			Source: "cyberspace-" + source,
			Attributes: map[string]string{
				"ip":              ca.IP,
				"source_provider": source,
				"seed":            seedValue,
			},
			FirstSeen: now,
			LastSeen:  now,
			Status:    "active",
		})
	}

	if ca.Cert != nil {
		for _, san := range ca.Cert.SANs {
			san = strings.TrimPrefix(san, "*.")
			if san != "" && san != seedValue {
				assets = append(assets, DiscoveredAsset{
					Type:   "domain",
					Value:  san,
					Source: "cyberspace-" + source + "-cert",
					Attributes: map[string]string{
						"issuer":          ca.Cert.Issuer,
						"source_provider": source,
						"seed":            seedValue,
					},
					FirstSeen: now,
					LastSeen:  now,
					Status:    "active",
				})
			}
		}
	}

	return assets
}
