package orchestrate

import (
	"code.yt-security.com/public/scanengine/core"

	"fmt"
	"log/slog"
	"net"
	"strings"
)

type TargetEnricher struct {
	portServiceMap map[int]string
}

func NewTargetEnricher() *TargetEnricher {
	return &TargetEnricher{
		portServiceMap: defaultPortServiceMap(),
	}
}

func (e *TargetEnricher) EnrichTargets(existing, newTargets []*core.Target) []*core.Target {
	merged := make([]*core.Target, 0, len(existing)+len(newTargets))
	seen := make(map[string]*core.Target)

	for _, t := range existing {
		key := targetUniqueKey(t)
		if _, ok := seen[key]; !ok {
			enriched := e.enrich(t)
			seen[key] = enriched
			merged = append(merged, enriched)
		}
	}

	for _, t := range newTargets {
		key := targetUniqueKey(t)
		if prev, ok := seen[key]; ok {
			e.mergeInto(prev, t)
		} else {
			enriched := e.enrich(t)
			seen[key] = enriched
			merged = append(merged, enriched)
		}
	}

	derived := e.deriveTargets(merged)
	for _, dt := range derived {
		key := targetUniqueKey(dt)
		if _, ok := seen[key]; !ok {
			seen[key] = dt
			merged = append(merged, dt)
		}
	}

	return merged
}

func (e *TargetEnricher) enrich(t *core.Target) *core.Target {
	enriched := &core.Target{
		Host:     t.Host,
		IP:       t.IP,
		Port:     t.Port,
		Protocol: t.Protocol,
		URL:      t.URL,
		Extra:    copyExtra(t.Extra),
	}

	if enriched.IP == "" && enriched.Host != "" && net.ParseIP(enriched.Host) != nil {
		enriched.IP = enriched.Host
	}

	if enriched.Protocol == "" && enriched.Port > 0 {
		if svc, ok := e.portServiceMap[enriched.Port]; ok {
			enriched.Protocol = svc
		} else {
			enriched.Protocol = "tcp"
		}
	}

	if enriched.URL == "" && enriched.Port > 0 {
		enriched.URL = e.buildURL(enriched)
	}

	return enriched
}

func (e *TargetEnricher) buildURL(t *core.Target) string {
	host := t.Host
	if host == "" {
		host = t.IP
	}
	if host == "" {
		return ""
	}

	proto := strings.ToLower(t.Protocol)

	switch {
	case proto == "https" || proto == "ssl" || t.Port == 443 || t.Port == 8443 || t.Port == 4443:
		if t.Port == 443 {
			return "https://" + host
		}
		return fmt.Sprintf("https://%s:%d", host, t.Port)
	case proto == "http" || isHTTPPort(t.Port):
		if t.Port == 80 {
			return "http://" + host
		}
		return fmt.Sprintf("http://%s:%d", host, t.Port)
	default:
		return ""
	}
}

func (e *TargetEnricher) deriveTargets(targets []*core.Target) []*core.Target {
	var derived []*core.Target

	hostPorts := make(map[string][]int)
	for _, t := range targets {
		host := t.Host
		if host == "" {
			host = t.IP
		}
		if host != "" && t.Port > 0 {
			hostPorts[host] = append(hostPorts[host], t.Port)
		}
	}

	for _, t := range targets {
		if t.Host != "" && t.IP == "" && net.ParseIP(t.Host) == nil {
			derived = append(derived, &core.Target{
				Host:     t.Host,
				Port:     0,
				Protocol: "tcp",
			})
		}
	}

	return derived
}

func (e *TargetEnricher) EnrichWithFindings(targets []*core.Target, findings []*core.Finding) []*core.Target {
	enriched := make([]*core.Target, 0, len(targets))

	findingMap := make(map[string][]*core.Finding)
	for _, f := range findings {
		if f.Target != nil {
			key := targetUniqueKey(f.Target)
			findingMap[key] = append(findingMap[key], f)
		}
	}

	for _, t := range targets {
		key := targetUniqueKey(t)
		enrichedTarget := &core.Target{
			Host:         t.Host,
			IP:           t.IP,
			Port:         t.Port,
			Protocol:     t.Protocol,
			URL:          t.URL,
			Service:      t.Service,
			Product:      t.Product,
			Version:      t.Version,
			Fingerprints: t.Fingerprints,
			Extra:        copyExtra(t.Extra),
		}

		if enrichedTarget.IP == "" && enrichedTarget.Host != "" && net.ParseIP(enrichedTarget.Host) != nil {
			enrichedTarget.IP = enrichedTarget.Host
		}

		if enrichedTarget.Protocol == "" && enrichedTarget.Port > 0 {
			if svc, ok := e.portServiceMap[enrichedTarget.Port]; ok {
				enrichedTarget.Protocol = svc
			} else {
				enrichedTarget.Protocol = "tcp"
			}
		}

		if enrichedTarget.URL == "" && enrichedTarget.Port > 0 {
			enrichedTarget.URL = e.buildURL(enrichedTarget)
		}

		if findings, ok := findingMap[key]; ok {
			for _, f := range findings {
				if f.Type == "fingerprint" && f.Data != nil {
					fp := core.Fingerprint{
						Confidence: f.Confidence,
						Source:     f.ModuleID,
					}
					if product, ok := f.Data["product"]; ok {
						fp.Product = product
						if enrichedTarget.Product == "" {
							enrichedTarget.Product = product
						}
					}
					if version, ok := f.Data["version"]; ok {
						fp.Version = version
						if enrichedTarget.Version == "" {
							enrichedTarget.Version = version
						}
					}
					if category, ok := f.Data["category"]; ok {
						fp.Category = category
					}
					enrichedTarget.Fingerprints = append(enrichedTarget.Fingerprints, fp)
				}

				if f.Type == "service" && f.Data != nil {
					if service, ok := f.Data["service"]; ok {
						if enrichedTarget.Service == "" {
							enrichedTarget.Service = service
						}
					}
				}
			}
		}

		enriched = append(enriched, enrichedTarget)
	}

	return enriched
}

func (e *TargetEnricher) mergeInto(dest, src *core.Target) {
	if dest.IP == "" && src.IP != "" {
		dest.IP = src.IP
	}
	if dest.URL == "" && src.URL != "" {
		dest.URL = src.URL
	}
	if dest.Protocol == "" && src.Protocol != "" {
		dest.Protocol = src.Protocol
	}
	if src.Service != "" {
		svcLower := strings.ToLower(src.Service)
		if dest.Service == "" || svcLower != "tcp" && svcLower != "udp" {
			dest.Service = src.Service
		}
	} else if dest.Service == "" && src.Protocol != "" {
		p := strings.ToLower(src.Protocol)
		if p != "tcp" && p != "udp" && !strings.HasPrefix(p, "http") {
			dest.Service = src.Protocol
		}
	}
	if src.Product != "" && dest.Product == "" {
		dest.Product = src.Product
	}
	if src.Version != "" && dest.Version == "" {
		dest.Version = src.Version
	}
	if len(src.Fingerprints) > 0 {
		dest.Fingerprints = append(dest.Fingerprints, src.Fingerprints...)
	}
	if src.Extra != nil {
		if dest.Extra == nil {
			dest.Extra = make(map[string]string)
		}
		for k, v := range src.Extra {
			if _, ok := dest.Extra[k]; !ok {
				dest.Extra[k] = v
			}
		}
	}
}

func targetUniqueKey(t *core.Target) string {
	host := t.Host
	if host == "" {
		host = t.IP
	}
	// Service 不参与 key：同一 host:port 的不同阶段可能有无 Service 的差异，
	// 应该合并为同一 target 而不是产生两条记录。
	return fmt.Sprintf("%s|%d", host, t.Port)
}

func copyExtra(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func isHTTPPort(port int) bool {
	httpPorts := map[int]bool{
		80: true, 8080: true, 8000: true, 8008: true,
		8888: true, 8081: true, 8443: true, 3000: true,
		4000: true, 5000: true, 9090: true, 8090: true,
		8088: true, 8899: true, 9000: true,
	}
	return httpPorts[port]
}

func defaultPortServiceMap() map[int]string {
	return map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http",
		8443:  "https",
		9090:  "http",
		27017: "mongodb",
	}
}

func init() {
	slog.Debug("[TargetEnricher] 目标传播引擎就绪")
}
