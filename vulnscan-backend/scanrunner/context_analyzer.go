package scanrunner

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"code.yt-security.com/public/scanengine/core"
)

// ContextAnalyzer correlates multiple findings from a single scan to produce
// higher-level risk assessments and attack chain insights.
type ContextAnalyzer struct {
	findings []*core.Finding
}

// CorrelationResult represents a discovered attack chain or correlated risk.
type CorrelationResult struct {
	ChainID     string   `json:"chain_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  int      `json:"confidence"`
	FindingIDs  []string `json:"finding_ids"`
	RiskScore   float64  `json:"risk_score"`
}

func NewContextAnalyzer(findings []*core.Finding) *ContextAnalyzer {
	return &ContextAnalyzer{findings: findings}
}

// Analyze runs all correlation rules and returns discovered chains.
func (ca *ContextAnalyzer) Analyze() []CorrelationResult {
	if len(ca.findings) < 2 {
		return nil
	}

	targetMap := ca.groupByTarget()

	var results []CorrelationResult

	for target, findings := range targetMap {
		results = append(results, ca.checkOpenPortWithWeakCreds(target, findings)...)
		results = append(results, ca.checkWebAppExposure(target, findings)...)
		results = append(results, ca.checkInfoLeakChain(target, findings)...)
		results = append(results, ca.checkDefaultCredentialsWithKnownCVE(target, findings)...)
		results = append(results, ca.checkUnpatchedServiceExposure(target, findings)...)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})

	if len(results) > 0 {
		slog.Info("[ContextAnalyzer] 关联分析完成",
			"chains_found", len(results),
			"top_chain", results[0].Title,
			"top_risk", results[0].RiskScore,
		)
	}

	return results
}

func (ca *ContextAnalyzer) groupByTarget() map[string][]*core.Finding {
	targetMap := make(map[string][]*core.Finding)
	for _, f := range ca.findings {
		if f.Target == nil {
			continue
		}
		key := f.Target.Host
		if key == "" {
			key = f.Target.IP
		}
		if key == "" {
			continue
		}
		targetMap[key] = append(targetMap[key], f)
	}
	return targetMap
}

// Rule 1: Open high-risk port + weak credentials = critical risk chain
func (ca *ContextAnalyzer) checkOpenPortWithWeakCreds(target string, findings []*core.Finding) []CorrelationResult {
	var openPorts []*core.Finding
	var weakCreds []*core.Finding

	highRiskPorts := map[int]bool{
		22: true, 23: true, 3389: true, 3306: true, 5432: true,
		1433: true, 6379: true, 27017: true, 11211: true, 9200: true,
	}

	for _, f := range findings {
		if f.Type == "port_open" && f.Target != nil && highRiskPorts[f.Target.Port] {
			openPorts = append(openPorts, f)
		}
		fType := strings.ToLower(f.Type)
		if strings.Contains(fType, "weak_pass") || strings.Contains(fType, "default_cred") ||
			strings.Contains(fType, "brute") || strings.Contains(fType, "unauth") {
			weakCreds = append(weakCreds, f)
		}
	}

	if len(openPorts) == 0 || len(weakCreds) == 0 {
		return nil
	}

	ids := collectIDs(openPorts, weakCreds)
	return []CorrelationResult{{
		ChainID:     fmt.Sprintf("chain-port-cred-%s", target),
		Title:       fmt.Sprintf("高危端口 + 弱凭据 (%s)", target),
		Description: fmt.Sprintf("目标 %s 存在高危端口开放且检测到弱凭据，攻击者可直接利用弱凭据获取服务访问权限", target),
		Severity:    "critical",
		Confidence:  95,
		FindingIDs:  ids,
		RiskScore:   9.5,
	}}
}

// Rule 2: Web app with multiple vuln types = comprehensive web exposure
func (ca *ContextAnalyzer) checkWebAppExposure(target string, findings []*core.Finding) []CorrelationResult {
	webVulnTypes := make(map[string]*core.Finding)
	webVulnCategories := []string{"sqli", "xss", "ssrf", "cmdi", "lfi", "ssti", "xxe", "rce"}

	for _, f := range findings {
		fType := strings.ToLower(f.Type)
		for _, cat := range webVulnCategories {
			if strings.Contains(fType, cat) {
				webVulnTypes[cat] = f
			}
		}
	}

	if len(webVulnTypes) < 2 {
		return nil
	}

	var relatedFindings []*core.Finding
	var vulnNames []string
	for name, f := range webVulnTypes {
		relatedFindings = append(relatedFindings, f)
		vulnNames = append(vulnNames, strings.ToUpper(name))
	}

	sort.Strings(vulnNames)

	riskScore := float64(5) + float64(len(webVulnTypes))*0.8
	if riskScore > 10 {
		riskScore = 10
	}

	return []CorrelationResult{{
		ChainID:     fmt.Sprintf("chain-webvuln-%s", target),
		Title:       fmt.Sprintf("多类型 Web 漏洞暴露 (%s)", target),
		Description: fmt.Sprintf("目标 %s 存在 %d 种 Web 漏洞类型: %s，表明 Web 应用安全防护严重不足", target, len(webVulnTypes), strings.Join(vulnNames, ", ")),
		Severity:    "critical",
		Confidence:  90,
		FindingIDs:  collectIDsSingle(relatedFindings),
		RiskScore:   riskScore,
	}}
}

// Rule 3: Information leak findings that together form a reconnaissance chain
func (ca *ContextAnalyzer) checkInfoLeakChain(target string, findings []*core.Finding) []CorrelationResult {
	var infoLeaks []*core.Finding
	infoTypes := make(map[string]bool)

	for _, f := range findings {
		fType := strings.ToLower(f.Type)
		if strings.Contains(fType, "info_leak") || strings.Contains(fType, "sensitive") ||
			strings.Contains(fType, "directory_listing") || strings.Contains(fType, "source_code") ||
			strings.Contains(fType, "backup_file") || strings.Contains(fType, "config_exposure") {
			infoLeaks = append(infoLeaks, f)
			infoTypes[fType] = true
		}
	}

	if len(infoTypes) < 3 {
		return nil
	}

	return []CorrelationResult{{
		ChainID:     fmt.Sprintf("chain-infoleak-%s", target),
		Title:       fmt.Sprintf("多维度信息泄露链 (%s)", target),
		Description: fmt.Sprintf("目标 %s 存在 %d 种信息泄露，攻击者可利用泄露的信息进行深入渗透", target, len(infoTypes)),
		Severity:    "high",
		Confidence:  85,
		FindingIDs:  collectIDsSingle(infoLeaks),
		RiskScore:   7.5,
	}}
}

// Rule 4: Default credentials + known CVE on same service
func (ca *ContextAnalyzer) checkDefaultCredentialsWithKnownCVE(target string, findings []*core.Finding) []CorrelationResult {
	var defaultCreds []*core.Finding
	var cveFindings []*core.Finding

	for _, f := range findings {
		fType := strings.ToLower(f.Type)
		if strings.Contains(fType, "default_cred") || strings.Contains(fType, "default_pass") {
			defaultCreds = append(defaultCreds, f)
		}
		if len(f.CVEIDs) > 0 {
			cveFindings = append(cveFindings, f)
		}
	}

	if len(defaultCreds) == 0 || len(cveFindings) == 0 {
		return nil
	}

	cveList := make([]string, 0)
	for _, f := range cveFindings {
		cveList = append(cveList, f.CVEIDs...)
	}
	if len(cveList) > 5 {
		cveList = cveList[:5]
	}

	ids := collectIDs(defaultCreds, cveFindings)
	return []CorrelationResult{{
		ChainID:     fmt.Sprintf("chain-cred-cve-%s", target),
		Title:       fmt.Sprintf("默认凭据 + 已知 CVE (%s)", target),
		Description: fmt.Sprintf("目标 %s 使用默认凭据且存在已知漏洞 (%s)，极易被自动化攻击工具利用", target, strings.Join(cveList, ", ")),
		Severity:    "critical",
		Confidence:  95,
		FindingIDs:  ids,
		RiskScore:   9.8,
	}}
}

// Rule 5: Unpatched/outdated service exposed on public port
func (ca *ContextAnalyzer) checkUnpatchedServiceExposure(target string, findings []*core.Finding) []CorrelationResult {
	var outdatedServices []*core.Finding
	var publicPorts []*core.Finding

	for _, f := range findings {
		fType := strings.ToLower(f.Type + " " + f.Title)
		if strings.Contains(fType, "outdated") || strings.Contains(fType, "end of life") ||
			strings.Contains(fType, "eol") || strings.Contains(fType, "版本过旧") {
			outdatedServices = append(outdatedServices, f)
		}
		if f.Type == "port_open" && f.Target != nil {
			publicPorts = append(publicPorts, f)
		}
	}

	if len(outdatedServices) == 0 || len(publicPorts) == 0 {
		return nil
	}

	ids := collectIDs(outdatedServices, publicPorts)
	return []CorrelationResult{{
		ChainID:     fmt.Sprintf("chain-eol-exposed-%s", target),
		Title:       fmt.Sprintf("过期服务公网暴露 (%s)", target),
		Description: fmt.Sprintf("目标 %s 存在已停止维护的服务版本对外暴露，缺乏安全补丁保护", target),
		Severity:    "high",
		Confidence:  80,
		FindingIDs:  ids,
		RiskScore:   7.0,
	}}
}

// GenerateCorrelationFindings converts correlation results into core.Finding objects
// that can be persisted alongside normal findings.
func GenerateCorrelationFindings(results []CorrelationResult, taskTargets []*core.Target) []*core.Finding {
	var findings []*core.Finding

	for _, cr := range results {
		f := &core.Finding{
			ModuleID:           "context_analyzer",
			Type:               "attack_chain",
			Category:           "vuln",
			Title:              cr.Title,
			Description:        cr.Description,
			Severity:           cr.Severity,
			Confidence:         cr.Confidence,
			Verified:           true,
			VerificationLevel:  core.VerifyExploit,
			VerificationDetail: fmt.Sprintf("关联分析：%d 条发现组成攻击链", len(cr.FindingIDs)),
			Data: map[string]string{
				"chain_id":    cr.ChainID,
				"finding_ids": strings.Join(cr.FindingIDs, ","),
				"risk_score":  fmt.Sprintf("%.1f", cr.RiskScore),
			},
		}

		if len(taskTargets) > 0 {
			f.Target = taskTargets[0]
		}

		findings = append(findings, f)
	}

	return findings
}

func collectIDs(groups ...[]*core.Finding) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, group := range groups {
		for _, f := range group {
			id := findingID(f)
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func collectIDsSingle(findings []*core.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, findingID(f))
	}
	return ids
}

func findingID(f *core.Finding) string {
	target := ""
	port := 0
	if f.Target != nil {
		target = f.Target.Host
		if target == "" {
			target = f.Target.IP
		}
		port = f.Target.Port
	}
	return fmt.Sprintf("%s:%d:%s:%s", target, port, f.ModuleID, f.Type)
}
