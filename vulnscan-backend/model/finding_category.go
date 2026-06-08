package model

import "strings"

var reconFindingTypes = map[string]struct{}{
	"host_alive":       {},
	"port_open":        {},
	"udp_port":         {},
	"service":          {},
	"web_page":         {},
	"web_info":         {},
	"dns_record":       {},
	"subdomain":        {},
	"cert_info":        {},
	"favicon":          {},
	"tech":             {},
	"api":              {},
	"waf":              {},
	"js_info":          {},
	"crawler":          {},
	"url":              {},
	"form":             {},
	"xhr":              {},
	"cdn_detected":     {},
	"zone_transfer":    {},
	"internal_ip_leak": {},
	"fingerprint":      {},
	"real_ip":          {},
	"email":            {},
	"ip_attribution":   {},
	"asn":              {},
	"organization":     {},
	"domain":           {},
	"ip_range":         {},
	"cyber_asset":      {},
}

var reconFindingModules = map[string]struct{}{
	"api_disc":        {},
	"company_recon":   {},
	"cyberspace":      {},
	"dir_scan":        {},
	"dns_all":         {},
	"email_collect":   {},
	"favicon":         {},
	"fpenhance":       {},
	"git_leak":        {},
	"ip_attr":         {},
	"js_analyze":      {},
	"nettopo":         {},
	"real_ip":         {},
	"screenshot":      {},
	"subdomain_brute": {},
	"tech_detect":     {},
	"waf_detect":      {},
	"web_crawl":       {},
	"web_fingerprint": {},
}

var discoverFindingModules = map[string]struct{}{
	"icmp_ping":     {},
	"port_scan":     {},
	"service_probe": {},
	"syn_scan":      {},
	"udp_scan":      {},
}

var vulnFindingModules = map[string]struct{}{
	"advanced_vuln":    {},
	"apisec":           {},
	"brute_force":      {},
	"cert_check":       {},
	"cmdi":             {},
	"credential_audit": {},
	"info_leak":        {},
	"jwt_sec":          {},
	"lfi":              {},
	"nosqli":           {},
	"nuclei-poc":       {},
	"sqli":             {},
	"ssrf":             {},
	"ssti":             {},
	"unauth":           {},
	"weak_pass":        {},
	"xss":              {},
	"xxe":              {},
}

func InferFindingCategory(moduleID, findingType string) string {
	moduleID = strings.TrimSpace(moduleID)
	findingType = strings.TrimSpace(findingType)

	if moduleID == "cert_check" && findingType == "cert_info" {
		return FindingCategoryRecon
	}

	if _, ok := vulnFindingModules[moduleID]; ok {
		return FindingCategoryVuln
	}

	if _, ok := reconFindingModules[moduleID]; ok {
		return FindingCategoryRecon
	}
	if _, ok := discoverFindingModules[moduleID]; ok {
		return FindingCategoryRecon
	}
	if _, ok := reconFindingTypes[findingType]; ok {
		return FindingCategoryRecon
	}
	return FindingCategoryVuln
}

// InferFindingCategoryWithSeverity extends InferFindingCategory with severity override:
// recon-module findings with severity >= high are promoted to vuln category.
func InferFindingCategoryWithSeverity(moduleID, findingType, severity string) string {
	cat := InferFindingCategory(moduleID, findingType)
	if cat == FindingCategoryRecon && (severity == "high" || severity == "critical") {
		return FindingCategoryVuln
	}
	return cat
}

func NormalizeFindingCategory(category, moduleID, findingType string) string {
	if strings.TrimSpace(category) == FindingCategoryRecon {
		return FindingCategoryRecon
	}
	return InferFindingCategory(moduleID, findingType)
}

// NormalizeFindingCategoryWithSeverity is severity-aware normalization.
func NormalizeFindingCategoryWithSeverity(category, moduleID, findingType, severity string) string {
	if strings.TrimSpace(category) == FindingCategoryRecon && severity != "high" && severity != "critical" {
		return FindingCategoryRecon
	}
	return InferFindingCategoryWithSeverity(moduleID, findingType, severity)
}
