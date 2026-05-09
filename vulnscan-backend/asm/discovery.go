package asm

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

type AssetCollector interface {
	Name() string
	Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error)
}

type DNSCollector struct{}

func (c *DNSCollector) Name() string { return "dns" }

func (c *DNSCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	if seed.Type != "domain" {
		return nil, nil
	}

	var assets []DiscoveredAsset

	ips, err := net.DefaultResolver.LookupHost(ctx, seed.Value)
	if err == nil {
		for _, ip := range ips {
			assets = append(assets, DiscoveredAsset{
				Type:   "ip",
				Value:  ip,
				Source: "dns-a",
				Attributes: map[string]string{
					"domain": seed.Value,
				},
			})
		}
	}

	mxRecords, err := net.DefaultResolver.LookupMX(ctx, seed.Value)
	if err == nil {
		for _, mx := range mxRecords {
			assets = append(assets, DiscoveredAsset{
				Type:   "domain",
				Value:  strings.TrimSuffix(mx.Host, "."),
				Source: "dns-mx",
				Attributes: map[string]string{
					"priority": fmt.Sprintf("%d", mx.Pref),
					"parent":   seed.Value,
				},
			})
		}
	}

	nsRecords, err := net.DefaultResolver.LookupNS(ctx, seed.Value)
	if err == nil {
		for _, ns := range nsRecords {
			assets = append(assets, DiscoveredAsset{
				Type:   "domain",
				Value:  strings.TrimSuffix(ns.Host, "."),
				Source: "dns-ns",
				Attributes: map[string]string{
					"parent": seed.Value,
				},
			})
		}
	}

	return assets, nil
}

type ReverseDNSCollector struct{}

func (c *ReverseDNSCollector) Name() string { return "rdns" }

func (c *ReverseDNSCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	if seed.Type != "ip" {
		return nil, nil
	}

	names, err := net.DefaultResolver.LookupAddr(ctx, seed.Value)
	if err != nil {
		return nil, nil
	}

	var assets []DiscoveredAsset
	for _, name := range names {
		assets = append(assets, DiscoveredAsset{
			Type:   "domain",
			Value:  strings.TrimSuffix(name, "."),
			Source: "rdns",
			Attributes: map[string]string{
				"ip": seed.Value,
			},
		})
	}

	return assets, nil
}

type CertCollector struct {
	client *http.Client
}

func (c *CertCollector) Name() string { return "cert-transparency" }

func (c *CertCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	if seed.Type != "domain" {
		return nil, nil
	}

	if c.client == nil {
		c.client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", seed.Value)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建crt.sh请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "VulnScan/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取crt.sh响应失败: %w", err)
	}

	var entries []struct {
		NameValue  string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("解析crt.sh响应失败: %w", err)
	}

	seen := make(map[string]bool)
	var assets []DiscoveredAsset

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true

			assets = append(assets, DiscoveredAsset{
				Type:   "domain",
				Value:  name,
				Source: "cert-transparency",
				Attributes: map[string]string{
					"parent": seed.Value,
					"issuer": entry.IssuerName,
				},
			})
		}
	}

	slog.Info("[+] CT日志收集完成", "domain", seed.Value, "subdomains", len(assets))
	return assets, nil
}
