package engine

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
)

type SmartTargetPropagator struct {
	dedup       *TargetDeduplicator
	prioritizer *TargetPrioritizer
	enricher    *TargetEnricher
	pruner      *TargetPruner
}

func NewSmartTargetPropagator() *SmartTargetPropagator {
	return &SmartTargetPropagator{
		dedup:       NewTargetDeduplicator(),
		prioritizer: NewTargetPrioritizer(),
		enricher:    NewTargetEnricher(),
		pruner:      NewTargetPruner(0.3, 5000),
	}
}

func (p *SmartTargetPropagator) Propagate(existing, newTargets []*Target, findings []*Finding) []*Target {
	if len(newTargets) == 0 {
		return existing
	}

	enriched := p.enricher.EnrichWithFindings(newTargets, findings)

	allTargets := append(existing, enriched...)

	deduped := p.dedup.SmartDedup(allTargets)

	sorted := p.prioritizer.SortByRisk(deduped, findings)

	pruned := p.pruner.Prune(sorted, findings)

	slog.Info("[TargetPropagator] 目标传播完成",
		"input", len(newTargets),
		"enriched", len(enriched),
		"after_dedup", len(deduped),
		"after_prune", len(pruned),
	)

	return pruned
}

type TargetDeduplicator struct{}

func NewTargetDeduplicator() *TargetDeduplicator {
	return &TargetDeduplicator{}
}

func (d *TargetDeduplicator) SmartDedup(targets []*Target) []*Target {
	wildcardMerged := d.mergeWildcards(targets)

	ipAggregated := d.aggregateIPRanges(wildcardMerged)

	return d.dedupByService(ipAggregated)
}

func (d *TargetDeduplicator) mergeWildcards(targets []*Target) []*Target {
	domainMap := make(map[string]*Target)

	for _, t := range targets {
		host := t.Host
		if host == "" {
			host = t.IP
		}
		if host == "" {
			continue
		}

		normalized := normalizeHost(host)

		if existing, ok := domainMap[normalized]; ok {
			d.mergeTargetInfo(existing, t)
		} else {
			domainMap[normalized] = t
		}
	}

	result := make([]*Target, 0, len(domainMap))
	for _, t := range domainMap {
		result = append(result, t)
	}

	return result
}

func normalizeHost(host string) string {
	host = strings.ToLower(host)
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	return host
}

func (d *TargetDeduplicator) aggregateIPRanges(targets []*Target) []*Target {
	ipGroups := make(map[string][]*Target)
	var nonIPs []*Target

	for _, t := range targets {
		ip := t.IP
		if ip == "" {
			ip = t.Host
		}
		if ip == "" || net.ParseIP(ip) == nil {
			nonIPs = append(nonIPs, t)
			continue
		}

		parsed := net.ParseIP(ip)
		if parsed.To4() != nil {
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				subnet := strings.Join(parts[:3], ".") + ".0/24"
				ipGroups[subnet] = append(ipGroups[subnet], t)
			}
		} else {
			ipGroups[ip] = append(ipGroups[ip], t)
		}
	}

	result := make([]*Target, 0, len(nonIPs)+len(targets))
	result = append(result, nonIPs...)
	for _, group := range ipGroups {
		result = append(result, group...)
	}

	return result
}

func (d *TargetDeduplicator) dedupByService(targets []*Target) []*Target {
	seen := make(map[string]*Target)

	for _, t := range targets {
		key := targetUniqueKey(t)

		if existing, ok := seen[key]; ok {
			d.mergeTargetInfo(existing, t)
		} else {
			seen[key] = t
		}
	}

	var result []*Target
	for _, t := range seen {
		result = append(result, t)
	}

	return result
}

func (d *TargetDeduplicator) mergeTargetInfo(dest, src *Target) {
	if dest.IP == "" && src.IP != "" {
		dest.IP = src.IP
	}
	if dest.URL == "" && src.URL != "" {
		dest.URL = src.URL
	}
	if dest.Protocol == "" && src.Protocol != "" {
		dest.Protocol = src.Protocol
	}
	if dest.Service == "" && src.Service != "" {
		dest.Service = src.Service
	}
	if dest.Product == "" && src.Product != "" {
		dest.Product = src.Product
	}
	if dest.Version == "" && src.Version != "" {
		dest.Version = src.Version
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

	if src.Fingerprints != nil {
		dest.Fingerprints = append(dest.Fingerprints, src.Fingerprints...)
	}
}

type TargetPrioritizer struct{}

func NewTargetPrioritizer() *TargetPrioritizer {
	return &TargetPrioritizer{}
}

func (p *TargetPrioritizer) SortByRisk(targets []*Target, findings []*Finding) []*Target {
	scoreMap := make(map[string]float64)

	for _, t := range targets {
		scoreMap[targetUniqueKey(t)] = p.baseScore(t)
	}

	for _, f := range findings {
		if f.Target == nil {
			continue
		}
		key := targetUniqueKey(f.Target)

		switch f.Type {
		case "vulnerability":
			scoreMap[key] += severityWeight(f.Severity) * 10
		case "fingerprint":
			scoreMap[key] += 2
		case "tech_stack":
			scoreMap[key] += 3
		case "waf":
			scoreMap[key] -= 3
		case "cdn":
			scoreMap[key] -= 2
		case "port":
			if f.Data != nil {
				if port, ok := f.Data["port"]; ok {
					if isHighRiskPort(port) {
						scoreMap[key] += 15
					}
				}
			}
		}
	}

	sort.SliceStable(targets, func(i, j int) bool {
		return scoreMap[targetUniqueKey(targets[i])] > scoreMap[targetUniqueKey(targets[j])]
	})

	return targets
}

func (p *TargetPrioritizer) baseScore(t *Target) float64 {
	score := 10.0

	if t.Port > 0 {
		score += 5
		if isHighRiskPort(fmt.Sprintf("%d", t.Port)) {
			score += 10
		}
	}

	if t.URL != "" {
		score += 8
	}

	if t.Service != "" {
		score += 3
	}

	return score
}

func severityWeight(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 4.0
	case "high":
		return 3.0
	case "medium":
		return 2.0
	case "low":
		return 1.0
	default:
		return 1.5
	}
}

func isHighRiskPort(port string) bool {
	highRiskPorts := map[string]bool{
		"22":    true,
		"23":    true,
		"3389":  true,
		"5900":  true,
		"6379":  true,
		"27017": true,
		"9200":  true,
		"11211": true,
		"2181":  true,
		"5432":  true,
		"3306":  true,
		"1433":  true,
		"1521":  true,
	}
	return highRiskPorts[port]
}

type TargetPruner struct {
	threshold  float64
	maxTargets int
}

func NewTargetPruner(threshold float64, maxTargets int) *TargetPruner {
	if threshold <= 0 {
		threshold = 0.3
	}
	if maxTargets <= 0 {
		maxTargets = 5000
	}
	return &TargetPruner{
		threshold:  threshold,
		maxTargets: maxTargets,
	}
}

func (p *TargetPruner) Prune(targets []*Target, findings []*Finding) []*Target {
	if len(targets) <= p.maxTargets {
		return targets
	}

	return targets[:p.maxTargets]
}
