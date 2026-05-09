package engine

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CVEEntry struct {
	CVEID        string   `json:"cve_id"`
	ProductName  string   `json:"product_name"`
	Versions     []string `json:"versions"`
	Severity     string   `json:"severity"`
	CVSSScore    float64  `json:"cvss_score"`
	Description  string   `json:"description"`
	References   []string `json:"references"`
	CWEIDs       []string `json:"cwe_ids"`
	VersionRange string   `json:"version_range,omitempty"`
}

type CVEDatabase struct {
	entries    []CVEEntry
	productIdx map[string][]int
	versionIdx map[string]map[string][]int
}

func NewCVEDatabase() *CVEDatabase {
	db := &CVEDatabase{
		productIdx: make(map[string][]int),
		versionIdx: make(map[string]map[string][]int),
	}
	db.loadDefaultCVEs()
	return db
}

func (db *CVEDatabase) AddEntry(entry CVEEntry) {
	idx := len(db.entries)
	db.entries = append(db.entries, entry)

	product := strings.ToLower(entry.ProductName)
	db.productIdx[product] = append(db.productIdx[product], idx)

	if _, ok := db.versionIdx[product]; !ok {
		db.versionIdx[product] = make(map[string][]int)
	}
	for _, v := range entry.Versions {
		db.versionIdx[product][v] = append(db.versionIdx[product][v], idx)
	}
}

func (db *CVEDatabase) MatchProduct(product string, version string) []CVEEntry {
	product = strings.ToLower(product)
	version = strings.ToLower(version)

	matched := make([]CVEEntry, 0)
	seen := make(map[string]bool)

	if idxs, ok := db.productIdx[product]; ok {
		for _, idx := range idxs {
			entry := db.entries[idx]
			if seen[entry.CVEID] {
				continue
			}

			if version == "" {
				matched = append(matched, entry)
				seen[entry.CVEID] = true
				continue
			}

			if db.versionMatches(version, entry.Versions) {
				matched = append(matched, entry)
				seen[entry.CVEID] = true
			}
		}
	}

	return matched
}

func (db *CVEDatabase) MatchFingerprint(fp Fingerprint) []CVEEntry {
	return db.MatchProduct(fp.Product, fp.Version)
}

func (db *CVEDatabase) MatchTarget(target *Target) []CVEEntry {
	matched := make([]CVEEntry, 0)
	seen := make(map[string]bool)

	if target.Product != "" {
		for _, cve := range db.MatchProduct(target.Product, target.Version) {
			if !seen[cve.CVEID] {
				matched = append(matched, cve)
				seen[cve.CVEID] = true
			}
		}
	}

	for _, fp := range target.Fingerprints {
		for _, cve := range db.MatchFingerprint(fp) {
			if !seen[cve.CVEID] {
				matched = append(matched, cve)
				seen[cve.CVEID] = true
			}
		}
	}

	return matched
}

func (db *CVEDatabase) versionMatches(targetVersion string, cveVersions []string) bool {
	if len(cveVersions) == 0 {
		return true
	}

	for _, cveVer := range cveVersions {
		if versionMatch(targetVersion, cveVer) {
			return true
		}
	}
	return false
}

func versionMatch(target, cveVer string) bool {
	target = normalizeVersion(target)
	cveVer = normalizeVersion(cveVer)

	if target == cveVer {
		return true
	}

	if strings.Contains(cveVer, ",") {
		return matchVersionRange(target, cveVer)
	}

	if strings.HasPrefix(cveVer, "<=") {
		cveVer = strings.TrimPrefix(cveVer, "<=")
		return compareVersions(target, cveVer) <= 0
	}

	if strings.HasPrefix(cveVer, "<") {
		cveVer = strings.TrimPrefix(cveVer, "<")
		return compareVersions(target, cveVer) < 0
	}

	if strings.HasPrefix(cveVer, ">=") {
		cveVer = strings.TrimPrefix(cveVer, ">=")
		return compareVersions(target, cveVer) >= 0
	}

	if strings.HasPrefix(cveVer, ">") {
		cveVer = strings.TrimPrefix(cveVer, ">")
		return compareVersions(target, cveVer) > 0
	}

	return false
}

func matchVersionRange(target, rangeStr string) bool {
	constraints := strings.Split(rangeStr, ",")
	for _, constraint := range constraints {
		constraint = strings.TrimSpace(constraint)
		if !versionMatch(target, constraint) {
			return false
		}
	}
	return true
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

func compareVersions(a, b string) int {
	partsA := splitVersion(a)
	partsB := splitVersion(b)

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var na, nb int
		if i < len(partsA) {
			na = partsA[i]
		}
		if i < len(partsB) {
			nb = partsB[i]
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	re := regexp.MustCompile(`\d+`)
	parts := re.FindAllString(v, -1)
	var nums []int
	for _, p := range parts {
		var n int
		fmt.Sscanf(p, "%d", &n)
		nums = append(nums, n)
	}
	return nums
}

type CVEMatcherModule struct {
	db *CVEDatabase
}

func NewCVEMatcherModule(db *CVEDatabase) *CVEMatcherModule {
	if db == nil {
		db = NewCVEDatabase()
	}
	return &CVEMatcherModule{db: db}
}

func (m *CVEMatcherModule) ID() string       { return "cve-matcher" }
func (m *CVEMatcherModule) Name() string     { return "CVE Matcher" }
func (m *CVEMatcherModule) Category() string { return "cve" }

func (m *CVEMatcherModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	var findings []*Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 10)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return &ModuleResult{
				ModuleID: m.ID(),
				Findings: findings,
				Duration: time.Since(start),
			}, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t *Target) {
			defer wg.Done()
			defer func() { <-sem }()

			matchedCVEs := m.db.MatchTarget(t)
			var localFindings []*Finding
			for _, cve := range matchedCVEs {
				localFindings = append(localFindings, &Finding{
					Target:      t,
					Type:        "cve",
					Title:       fmt.Sprintf("%s: %s", cve.CVEID, cve.Description),
					Description: cve.Description,
					Severity:    cve.Severity,
					Confidence:  80,
					Evidence: fmt.Sprintf("Product: %s, Version: %s",
						t.Product, t.Version),
					Timestamp:   time.Now(),
					CVEIDs:      []string{cve.CVEID},
					CWEIDs:      cve.CWEIDs,
					CVSSScore:   cve.CVSSScore,
					Remediation: "升级到最新版本",
				})
			}

			if len(localFindings) > 0 {
				mu.Lock()
				findings = append(findings, localFindings...)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()

	slog.Info("[CVE-Matcher] 匹配完成",
		"targets", len(targets),
		"findings", len(findings),
		"duration", time.Since(start),
	)

	return &ModuleResult{
		ModuleID: m.ID(),
		Findings: findings,
		Duration: time.Since(start),
	}, nil
}

func (db *CVEDatabase) loadDefaultCVEs() {
	defaultCVEs := []CVEEntry{
		{
			CVEID:       "CVE-2021-44228",
			ProductName: "log4j",
			Versions:    []string{"<2.17.0"},
			Severity:    "critical",
			CVSSScore:   10.0,
			Description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints",
			CWEIDs:      []string{"CWE-502"},
		},
		{
			CVEID:       "CVE-2021-41773",
			ProductName: "apache",
			Versions:    []string{"2.4.49"},
			Severity:    "high",
			CVSSScore:   7.5,
			Description: "Apache HTTP Server 2.4.49 path traversal",
			CWEIDs:      []string{"CWE-22"},
		},
		{
			CVEID:       "CVE-2022-22965",
			ProductName: "spring",
			Versions:    []string{"<5.3.18"},
			Severity:    "critical",
			CVSSScore:   9.8,
			Description: "Spring Framework RCE via Data Binding",
			CWEIDs:      []string{"CWE-94"},
		},
		{
			CVEID:       "CVE-2023-44487",
			ProductName: "nginx",
			Versions:    []string{"<1.25.3"},
			Severity:    "high",
			CVSSScore:   7.5,
			Description: "HTTP/2 Rapid Reset Attack",
			CWEIDs:      []string{"CWE-400"},
		},
		{
			CVEID:       "CVE-2021-3129",
			ProductName: "laravel",
			Versions:    []string{"<8.4.3"},
			Severity:    "critical",
			CVSSScore:   9.8,
			Description: "Laravel Ignition RCE via file_get_contents and file_put_contents",
			CWEIDs:      []string{"CWE-78"},
		},
		{
			CVEID:       "CVE-2022-0543",
			ProductName: "redis",
			Versions:    []string{"<6.2.7"},
			Severity:    "critical",
			CVSSScore:   10.0,
			Description: "Redis Lua scripting sandbox escape",
			CWEIDs:      []string{"CWE-78"},
		},
		{
			CVEID:       "CVE-2022-24999",
			ProductName: "express",
			Versions:    []string{"<4.17.3"},
			Severity:    "high",
			CVSSScore:   7.5,
			Description: "Express.js qs prototype pollution",
			CWEIDs:      []string{"CWE-1321"},
		},
		{
			CVEID:       "CVE-2023-22515",
			ProductName: "confluence",
			Versions:    []string{"<8.5.1"},
			Severity:    "critical",
			CVSSScore:   10.0,
			Description: "Confluence Data Center and Server Broken Access Control",
			CWEIDs:      []string{"CWE-284"},
		},
	}

	for _, cve := range defaultCVEs {
		db.AddEntry(cve)
	}

	slog.Info("[CVE-DB] 已加载默认CVE库", "count", len(defaultCVEs))
}
