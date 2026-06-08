package aicompliance

import (
	"strings"
)

// ClauseEntry 合规条款条目。
type ClauseEntry struct {
	Framework string
	Clause    string
	Title     string
	Summary   string
	VulnTypes []string // 关联的漏洞类型
}

// ComplianceRAG 合规知识 RAG 存储。
type ComplianceRAG struct {
	entries []ClauseEntry
}

// NewComplianceRAG 创建合规 RAG。
func NewComplianceRAG() *ComplianceRAG {
	r := &ComplianceRAG{}
	r.loadBuiltinEntries()
	return r
}

// Search 基于关键词搜索相关条款。
func (r *ComplianceRAG) Search(query string, topK int) []ClauseEntry {
	queryLower := strings.ToLower(query)
	tokens := strings.Fields(queryLower)

	type scored struct {
		entry ClauseEntry
		score float64
	}

	var results []scored
	for _, e := range r.entries {
		text := strings.ToLower(e.Framework + " " + e.Clause + " " + e.Title + " " + e.Summary +
			" " + strings.Join(e.VulnTypes, " "))
		var score float64
		for _, t := range tokens {
			if strings.Contains(text, t) {
				score += 1.0
			}
		}
		if score > 0 {
			results = append(results, scored{entry: e, score: score})
		}
	}

	// simple sort
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].score > results[i].score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	if len(results) > topK {
		results = results[:topK]
	}
	out := make([]ClauseEntry, len(results))
	for i, r := range results {
		out[i] = r.entry
	}
	return out
}

// SearchByVulnType 按漏洞类型搜索关联条款。
func (r *ComplianceRAG) SearchByVulnType(vulnType string, topK int) []ClauseEntry {
	var results []ClauseEntry
	vulnLower := strings.ToLower(vulnType)
	for _, e := range r.entries {
		for _, vt := range e.VulnTypes {
			if strings.Contains(strings.ToLower(vt), vulnLower) {
				results = append(results, e)
				break
			}
		}
	}
	if len(results) > topK {
		results = results[:topK]
	}
	return results
}

func (r *ComplianceRAG) loadBuiltinEntries() {
	r.entries = []ClauseEntry{
		// 等保2.0
		{Framework: "等保2.0", Clause: "8.1.4.1", Title: "入侵防范",
			Summary:   "应遵循最小安装的原则，仅安装需要的组件和应用程序；应关闭不需要的系统服务、默认共享和高危端口",
			VulnTypes: []string{"open_port", "unnecessary_service"}},
		{Framework: "等保2.0", Clause: "8.1.4.2", Title: "恶意代码防范",
			Summary:   "应安装防恶意代码软件，并及时更新特征库；应对网络通信和主机进行恶意代码检测",
			VulnTypes: []string{"malware", "webshell"}},
		{Framework: "等保2.0", Clause: "8.1.3.1", Title: "身份鉴别",
			Summary:   "应对登录的用户进行身份标识和鉴别；身份标识具有唯一性；鉴别信息具有复杂度要求；应具有登录失败处理功能",
			VulnTypes: []string{"weak_password", "brute_force", "auth_bypass", "unauth"}},
		{Framework: "等保2.0", Clause: "8.1.3.2", Title: "访问控制",
			Summary:   "应对登录的用户分配账户和权限；应重命名或删除默认账户；应及时删除或停用多余、过期账户",
			VulnTypes: []string{"idor", "privilege_escalation", "unauth"}},
		{Framework: "等保2.0", Clause: "8.1.3.4", Title: "安全审计",
			Summary:   "应启用安全审计功能，审计覆盖到每个用户；应对审计记录进行保护",
			VulnTypes: []string{"log_injection", "audit_bypass"}},
		{Framework: "等保2.0", Clause: "8.1.4.4", Title: "数据完整性",
			Summary:   "应采用校验技术或密码技术保证重要数据在传输过程中的完整性和保密性",
			VulnTypes: []string{"sqli", "data_tampering", "mitm"}},
		{Framework: "等保2.0", Clause: "8.1.4.5", Title: "数据保密性",
			Summary:   "应采用密码技术保证重要数据在传输过程中的保密性；应采用密码技术保证重要数据在存储过程中的保密性",
			VulnTypes: []string{"cleartext_transmission", "weak_crypto", "info_leak"}},
		{Framework: "等保2.0", Clause: "8.1.2.3", Title: "通信传输",
			Summary:   "应采用密码技术保证通信过程中数据的完整性和保密性",
			VulnTypes: []string{"ssl_expired", "weak_ssl", "cleartext_transmission"}},
		{Framework: "等保2.0", Clause: "8.1.4.6", Title: "Web应用安全",
			Summary:   "应对Web应用进行安全编码和安全测试；应对用户输入进行验证和过滤",
			VulnTypes: []string{"sqli", "xss", "cmdi", "lfi", "ssrf", "ssti", "xxe"}},

		// ISO 27001
		{Framework: "ISO27001", Clause: "A.8.6", Title: "Capacity management",
			Summary:   "The use of resources shall be monitored and adjusted",
			VulnTypes: []string{"dos", "resource_exhaustion"}},
		{Framework: "ISO27001", Clause: "A.8.9", Title: "Configuration management",
			Summary:   "Configurations shall be established, documented, implemented, monitored and reviewed",
			VulnTypes: []string{"misconfig", "default_creds", "unnecessary_service"}},
		{Framework: "ISO27001", Clause: "A.8.12", Title: "Data leakage prevention",
			Summary:   "Data leakage prevention measures shall be applied to systems, networks and endpoints",
			VulnTypes: []string{"info_leak", "sensitive_data_exposure", "git_leak"}},
		{Framework: "ISO27001", Clause: "A.8.24", Title: "Use of cryptography",
			Summary:   "Rules for the effective use of cryptography shall be defined and implemented",
			VulnTypes: []string{"weak_crypto", "weak_ssl", "cleartext_transmission"}},
		{Framework: "ISO27001", Clause: "A.8.26", Title: "Application security requirements",
			Summary:   "Information security requirements shall be identified and specified for development",
			VulnTypes: []string{"sqli", "xss", "cmdi", "ssrf", "auth_bypass"}},
		{Framework: "ISO27001", Clause: "A.8.28", Title: "Secure coding",
			Summary:   "Secure coding principles shall be applied to software development",
			VulnTypes: []string{"sqli", "xss", "cmdi", "lfi", "ssti", "xxe", "deserialization"}},

		// PCI DSS
		{Framework: "PCI-DSS", Clause: "6.2.4", Title: "软件工程安全",
			Summary:   "注入攻击防护：SQL注入、OS命令注入、LDAP注入等",
			VulnTypes: []string{"sqli", "cmdi", "ldap_injection", "nosqli"}},
		{Framework: "PCI-DSS", Clause: "6.2.4.2", Title: "XSS防护",
			Summary:   "跨站脚本攻击防护",
			VulnTypes: []string{"xss", "dom_xss"}},
		{Framework: "PCI-DSS", Clause: "4.2.1", Title: "加密传输",
			Summary:   "持卡人数据在开放公共网络传输时须使用强加密",
			VulnTypes: []string{"weak_ssl", "cleartext_transmission", "ssl_expired"}},
		{Framework: "PCI-DSS", Clause: "8.3.6", Title: "密码复杂度",
			Summary:   "密码最小长度12字符，含数字和字母",
			VulnTypes: []string{"weak_password", "brute_force"}},
	}
}
