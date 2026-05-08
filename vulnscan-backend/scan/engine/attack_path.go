package engine

import (
	"fmt"
	"sort"
	"strings"
)

type AttackPathNode struct {
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Service  string            `json:"service"`
	Findings []*FindingSummary `json:"findings"`
}

type FindingSummary struct {
	ModuleID   string `json:"module_id"`
	Type       string `json:"type"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Confidence int    `json:"confidence"`
}

type AttackPath struct {
	Host        string           `json:"host"`
	RiskScore   float64          `json:"risk_score"`
	Nodes       []AttackPathNode `json:"nodes"`
	Suggestions []string         `json:"suggestions"`
}

type AttackPathAnalyzer struct {
	severityWeights map[string]float64
}

func NewAttackPathAnalyzer() *AttackPathAnalyzer {
	return &AttackPathAnalyzer{
		severityWeights: map[string]float64{
			"critical": 10.0,
			"high":     7.0,
			"medium":   4.0,
			"low":      1.0,
			"info":     0.5,
		},
	}
}

func (a *AttackPathAnalyzer) Analyze(targets []*Target, findings []*Finding) []AttackPath {
	hostFindings := make(map[string][]*Finding)
	hostTargets := make(map[string][]*Target)

	for _, t := range targets {
		host := resolveHost(t)
		if host != "" {
			hostTargets[host] = append(hostTargets[host], t)
		}
	}
	for _, f := range findings {
		if f.Target != nil {
			host := resolveHost(f.Target)
			if host != "" {
				hostFindings[host] = append(hostFindings[host], f)
			}
		}
	}

	var paths []AttackPath
	for host, hTargets := range hostTargets {
		hFindings := hostFindings[host]
		path := a.buildPath(host, hTargets, hFindings)
		if len(path.Nodes) > 0 || len(path.Suggestions) > 0 {
			paths = append(paths, path)
		}
	}

	sort.Slice(paths, func(i, j int) bool {
		return paths[i].RiskScore > paths[j].RiskScore
	})

	return paths
}

func (a *AttackPathAnalyzer) buildPath(host string, targets []*Target, findings []*Finding) AttackPath {
	path := AttackPath{Host: host}

	portMap := make(map[int]*AttackPathNode)
	for _, t := range targets {
		if t.Port == 0 {
			continue
		}
		if _, ok := portMap[t.Port]; !ok {
			portMap[t.Port] = &AttackPathNode{
				Host:    host,
				Port:    t.Port,
				Service: t.Protocol,
			}
		}
	}

	var riskScore float64
	typeCount := make(map[string]int)

	for _, f := range findings {
		port := 0
		if f.Target != nil {
			port = f.Target.Port
		}

		summary := &FindingSummary{
			ModuleID:   f.ModuleID,
			Type:       f.Type,
			Title:      f.Title,
			Severity:   f.Severity,
			Confidence: f.Confidence,
		}

		if node, ok := portMap[port]; ok {
			node.Findings = append(node.Findings, summary)
		} else if port > 0 {
			portMap[port] = &AttackPathNode{
				Host:     host,
				Port:     port,
				Findings: []*FindingSummary{summary},
			}
		}

		weight := a.severityWeights[strings.ToLower(f.Severity)]
		riskScore += weight * float64(f.Confidence) / 100.0
		typeCount[f.Type]++
	}

	for _, node := range portMap {
		path.Nodes = append(path.Nodes, *node)
	}
	sort.Slice(path.Nodes, func(i, j int) bool {
		return nodeRisk(path.Nodes[i]) > nodeRisk(path.Nodes[j])
	})

	path.RiskScore = riskScore
	path.Suggestions = a.generateSuggestions(host, targets, findings, typeCount)

	return path
}

func (a *AttackPathAnalyzer) generateSuggestions(host string, targets []*Target, findings []*Finding, typeCount map[string]int) []string {
	var suggestions []string

	hasWebVuln := typeCount["sqli_error"] > 0 || typeCount["sqli_boolean"] > 0 ||
		typeCount["sqli_time"] > 0 || typeCount["sqli_union"] > 0
	hasXSS := typeCount["xss_reflected"] > 0 || typeCount["xss_dom"] > 0
	hasBrute := typeCount["brute_success"] > 0
	hasWeakCred := false
	hasSensitivePorts := false

	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "弱口令") || strings.Contains(strings.ToLower(f.Title), "weak") {
			hasWeakCred = true
		}
	}

	sensitiveServices := map[string]bool{
		"ssh": true, "rdp": true, "mysql": true, "postgresql": true,
		"redis": true, "mongodb": true, "mssql": true, "ftp": true,
	}
	for _, t := range targets {
		if sensitiveServices[strings.ToLower(t.Protocol)] {
			hasSensitivePorts = true
			break
		}
	}

	if hasWebVuln {
		suggestions = append(suggestions, fmt.Sprintf("[高危] %s 存在SQL注入漏洞，攻击者可读取/修改数据库，建议立即修复参数化查询", host))
	}
	if hasXSS {
		suggestions = append(suggestions, fmt.Sprintf("[中危] %s 存在XSS漏洞，可被利用进行钓鱼攻击或窃取Cookie，建议实施输出编码和CSP", host))
	}
	if hasWebVuln && hasXSS {
		suggestions = append(suggestions, fmt.Sprintf("[攻击链] %s: XSS+SQLi组合可实现完整数据窃取链 (XSS窃取管理员Cookie → SQLi读取数据库)", host))
	}
	if hasBrute || hasWeakCred {
		suggestions = append(suggestions, fmt.Sprintf("[高危] %s 存在弱口令/爆破成功记录，攻击者可直接获取服务访问权限", host))
	}
	if hasSensitivePorts {
		suggestions = append(suggestions, fmt.Sprintf("[风险] %s 暴露了敏感服务端口(数据库/远程管理)，建议配置网络ACL限制访问来源", host))
	}
	if hasSensitivePorts && (hasBrute || hasWeakCred) {
		suggestions = append(suggestions, fmt.Sprintf("[攻击链] %s: 敏感端口暴露+弱口令 = 可直接远程入侵，优先级最高", host))
	}

	return suggestions
}

func resolveHost(t *Target) string {
	if t.Host != "" {
		return t.Host
	}
	return t.IP
}

func nodeRisk(n AttackPathNode) float64 {
	severityW := map[string]float64{
		"critical": 10, "high": 7, "medium": 4, "low": 1,
	}
	var risk float64
	for _, f := range n.Findings {
		risk += severityW[strings.ToLower(f.Severity)]
	}
	return risk
}
