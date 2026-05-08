package intel

import (
	"fmt"
	"log/slog"
	"strings"
)

type VulnMatcher struct {
	cveDB   map[string]*CVEEntry
	cpeMaps []FingerprintCPEMapping
}

func NewVulnMatcher() *VulnMatcher {
	return &VulnMatcher{
		cveDB:   make(map[string]*CVEEntry),
		cpeMaps: builtinCPEMappings(),
	}
}

func (m *VulnMatcher) LoadCVEs(entries []CVEEntry) {
	for i := range entries {
		m.cveDB[entries[i].ID] = &entries[i]
	}
	slog.Info("[+] CVE数据库加载完成", "count", len(entries))
}

func (m *VulnMatcher) MatchByFingerprint(product, version string) []VulnMatch {
	cpes := m.findCPEs(product, version)
	if len(cpes) == 0 {
		return nil
	}

	var matches []VulnMatch
	for _, cve := range m.cveDB {
		for _, cpeCVE := range cve.CPE {
			for _, cpeTarget := range cpes {
				if cpeMatch(cpeCVE, cpeTarget) {
					matches = append(matches, VulnMatch{
						CVE:        *cve,
						MatchedCPE: cpeTarget,
						MatchType:  "cpe_match",
						Confidence: 80,
					})
				}
			}
		}
	}

	return matches
}

func (m *VulnMatcher) MatchByCVE(cveID string) *CVEEntry {
	return m.cveDB[cveID]
}

func (m *VulnMatcher) findCPEs(product, version string) []string {
	productLower := strings.ToLower(product)

	for _, mapping := range m.cpeMaps {
		if strings.ToLower(mapping.Product) == productLower {
			if version == "" || mapping.Version == "" || mapping.Version == "*" {
				return mapping.CPEMatches
			}
			if versionMatch(version, mapping.Version) {
				return mapping.CPEMatches
			}
		}
	}

	cpe := fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", productLower, version)
	return []string{cpe}
}

func cpeMatch(cveCPE, targetCPE string) bool {
	cveParts := strings.Split(cveCPE, ":")
	targetParts := strings.Split(targetCPE, ":")

	minLen := len(cveParts)
	if len(targetParts) < minLen {
		minLen = len(targetParts)
	}

	for i := 0; i < minLen; i++ {
		if cveParts[i] == "*" || targetParts[i] == "*" {
			continue
		}
		if !strings.EqualFold(cveParts[i], targetParts[i]) {
			return false
		}
	}

	return true
}

func versionMatch(actual, pattern string) bool {
	if pattern == "*" {
		return true
	}
	return strings.HasPrefix(actual, pattern) || actual == pattern
}

func (m *VulnMatcher) GetCPEMappings() []FingerprintCPEMapping {
	return m.cpeMaps
}

func (m *VulnMatcher) AddCPEMapping(mapping FingerprintCPEMapping) {
	for i := range m.cpeMaps {
		if strings.EqualFold(m.cpeMaps[i].Product, mapping.Product) && m.cpeMaps[i].Version == mapping.Version {
			m.cpeMaps[i].CPEMatches = mapping.CPEMatches
			return
		}
	}
	m.cpeMaps = append(m.cpeMaps, mapping)
}

func (m *VulnMatcher) UpdateCPEMapping(product string, fn func(*FingerprintCPEMapping)) bool {
	for i := range m.cpeMaps {
		if strings.EqualFold(m.cpeMaps[i].Product, product) {
			fn(&m.cpeMaps[i])
			return true
		}
	}
	return false
}

func (m *VulnMatcher) DeleteCPEMapping(product string) bool {
	for i := range m.cpeMaps {
		if strings.EqualFold(m.cpeMaps[i].Product, product) {
			m.cpeMaps = append(m.cpeMaps[:i], m.cpeMaps[i+1:]...)
			return true
		}
	}
	return false
}

func builtinCPEMappings() []FingerprintCPEMapping {
	return []FingerprintCPEMapping{
		{Product: "Nginx", Version: "*", CPEMatches: []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}},
		{Product: "Apache", Version: "*", CPEMatches: []string{"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}},
		{Product: "Tomcat", Version: "*", CPEMatches: []string{"cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"}},
		{Product: "IIS", Version: "*", CPEMatches: []string{"cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*"}},
		{Product: "WordPress", Version: "*", CPEMatches: []string{"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"}},
		{Product: "MySQL", Version: "*", CPEMatches: []string{"cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"}},
		{Product: "PostgreSQL", Version: "*", CPEMatches: []string{"cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"}},
		{Product: "Redis", Version: "*", CPEMatches: []string{"cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"}},
		{Product: "Jenkins", Version: "*", CPEMatches: []string{"cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"}},
		{Product: "Grafana", Version: "*", CPEMatches: []string{"cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"}},
		{Product: "Nacos", Version: "*", CPEMatches: []string{"cpe:2.3:a:alibaba:nacos:*:*:*:*:*:*:*:*"}},
		{Product: "Spring Boot", Version: "*", CPEMatches: []string{"cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*"}},
		{Product: "Elasticsearch", Version: "*", CPEMatches: []string{"cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"}},
		{Product: "MongoDB", Version: "*", CPEMatches: []string{"cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"}},
		{Product: "PHP", Version: "*", CPEMatches: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}},
		{Product: "OpenSSH", Version: "*", CPEMatches: []string{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}},
	}
}
