// Package aireport 提供 LLM 驱动的漏洞报告自动生成能力。
//
// 扫描完成后，自动为每个漏洞生成人类可读的描述、影响分析、
// 修复建议和风险评级，节省安全工程师 60%+ 报告编写时间。
package aireport

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// VulnContext 漏洞上下文，用于生成报告。
type VulnContext struct {
	Type        string `json:"type"`        // sqli/xss/rce/ssrf 等
	Target      string `json:"target"`      // 目标地址
	Severity    string `json:"severity"`    // critical/high/medium/low/info
	Title       string `json:"title"`       // 原始标题
	Evidence    string `json:"evidence"`    // 漏洞证据
	Payload     string `json:"payload"`     // 使用的 payload
	ModuleID    string `json:"module_id"`   // 检测模块
	Product     string `json:"product"`     // 目标产品/框架
	Description string `json:"description"` // 原始描述
}

// ReportOutput 生成的报告内容。
type ReportOutput struct {
	Title         string   `json:"title"`          // 专业标题
	Summary       string   `json:"summary"`        // 漏洞概述（1-2 句）
	Description   string   `json:"description"`    // 详细描述
	Impact        string   `json:"impact"`         // 影响分析
	Reproduction  string   `json:"reproduction"`   // 复现步骤
	Remediation   string   `json:"remediation"`    // 修复建议
	References    []string `json:"references"`     // 参考链接
	CVSSEstimate  string   `json:"cvss_estimate"`  // 预估 CVSS
	RiskLevel     string   `json:"risk_level"`     // 风险等级
	AffectedScope string   `json:"affected_scope"` // 影响范围
}

// BatchReportRequest 批量报告生成请求。
type BatchReportRequest struct {
	Vulns     []VulnContext `json:"vulns"`
	TargetOrg string        `json:"target_org"` // 目标组织名称
	ScanTime  string        `json:"scan_time"`  // 扫描时间
	ScanScope string        `json:"scan_scope"` // 扫描范围描述
}

// ExecutiveSummary 管理层摘要。
type ExecutiveSummary struct {
	Overview         string `json:"overview"`
	CriticalCount    int    `json:"critical_count"`
	HighCount        int    `json:"high_count"`
	MediumCount      int    `json:"medium_count"`
	LowCount         int    `json:"low_count"`
	TopRisks         string `json:"top_risks"`
	Recommendations  string `json:"recommendations"`
	ComplianceImpact string `json:"compliance_impact"`
}

// Service AI 报告生成服务。
type Service struct {
	ai    ai.Service
	model string
}

// NewService 创建 AI 报告生成服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{ai: aiSvc, model: model}
}

// GenerateVulnReport 为单个漏洞生成详细报告。
func (s *Service) GenerateVulnReport(ctx context.Context, vuln *VulnContext) (*ReportOutput, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildVulnReportPrompt(vuln)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: vulnReportSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM report generation failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseReportResponse(resp.Choices[0].Message.Content)
}

// GenerateExecutiveSummary 为整次扫描生成管理层摘要。
func (s *Service) GenerateExecutiveSummary(ctx context.Context, req *BatchReportRequest) (*ExecutiveSummary, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildExecutiveSummaryPrompt(req)

	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: executiveSummarySystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM executive summary failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseExecutiveSummaryResponse(resp.Choices[0].Message.Content)
}

const vulnReportSystemPrompt = `你是一位资深安全顾问，负责为客户撰写专业的漏洞报告。

报告要求：
1. 语言专业但清晰，技术人员和管理者都能理解
2. 复现步骤要具体可操作
3. 修复建议要包含具体代码示例或配置
4. 影响分析要结合业务场景

请以 JSON 格式返回：
{"title":"","summary":"","description":"","impact":"","reproduction":"","remediation":"","references":[],"cvss_estimate":"","risk_level":"","affected_scope":""}`

const executiveSummarySystemPrompt = `你是一位资深安全顾问，负责为客户管理层撰写安全评估摘要。

摘要要求：
1. 语言简洁专业，面向非技术管理层
2. 突出业务风险而非技术细节
3. 给出优先级排序的整改建议
4. 提及可能的合规影响（等保/ISO27001/GDPR等）

请以 JSON 格式返回：
{"overview":"","critical_count":0,"high_count":0,"medium_count":0,"low_count":0,"top_risks":"","recommendations":"","compliance_impact":""}`

func buildVulnReportPrompt(vuln *VulnContext) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 漏洞类型: %s\n", vuln.Type))
	sb.WriteString(fmt.Sprintf("## 严重级别: %s\n", vuln.Severity))
	sb.WriteString(fmt.Sprintf("## 目标: %s\n", vuln.Target))
	if vuln.Product != "" {
		sb.WriteString(fmt.Sprintf("## 产品/框架: %s\n", vuln.Product))
	}
	sb.WriteString(fmt.Sprintf("## 原始标题: %s\n", vuln.Title))
	if vuln.Payload != "" {
		sb.WriteString(fmt.Sprintf("## 使用的 Payload: %s\n", vuln.Payload))
	}
	if vuln.Evidence != "" {
		evidence := vuln.Evidence
		if len(evidence) > 1500 {
			evidence = evidence[:1500] + "...(truncated)"
		}
		sb.WriteString(fmt.Sprintf("\n## 证据:\n%s\n", evidence))
	}
	if vuln.Description != "" {
		sb.WriteString(fmt.Sprintf("\n## 原始描述:\n%s\n", vuln.Description))
	}
	sb.WriteString("\n请生成详细的专业漏洞报告。")
	return sb.String()
}

func buildExecutiveSummaryPrompt(req *BatchReportRequest) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 目标组织: %s\n", req.TargetOrg))
	sb.WriteString(fmt.Sprintf("## 扫描时间: %s\n", req.ScanTime))
	sb.WriteString(fmt.Sprintf("## 扫描范围: %s\n\n", req.ScanScope))

	sb.WriteString("## 发现的漏洞列表:\n\n")
	for i, v := range req.Vulns {
		if i >= 30 {
			sb.WriteString(fmt.Sprintf("... 以及其他 %d 个漏洞\n", len(req.Vulns)-30))
			break
		}
		sb.WriteString(fmt.Sprintf("- [%s] %s @ %s (%s)\n", v.Severity, v.Title, v.Target, v.Type))
	}

	sb.WriteString("\n请生成面向管理层的安全评估摘要。")
	return sb.String()
}

func parseReportResponse(content string) (*ReportOutput, error) {
	content = extractJSON(content)
	var result ReportOutput
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse report response: %w", err)
	}
	return &result, nil
}

func parseExecutiveSummaryResponse(content string) (*ExecutiveSummary, error) {
	content = extractJSON(content)
	var result ExecutiveSummary
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse executive summary response: %w", err)
	}
	return &result, nil
}

func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		lines := strings.Split(s, "\n")
		var jsonLines []string
		inBlock := false
		for _, line := range lines {
			if strings.HasPrefix(line, "```") {
				inBlock = !inBlock
				continue
			}
			if inBlock {
				jsonLines = append(jsonLines, line)
			}
		}
		s = strings.Join(jsonLines, "\n")
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}
