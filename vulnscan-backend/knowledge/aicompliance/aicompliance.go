// Package aicompliance 提供 LLM 驱动的合规知识问答和漏洞-合规映射。
//
// 基于 RAG 检索增强：内置等保2.0、ISO27001、GDPR 等合规框架知识，
// 将扫描发现的漏洞自动映射到对应合规条款，并生成整改建议。
package aicompliance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// ComplianceQuery 合规查询请求。
type ComplianceQuery struct {
	Question string `json:"question"` // 自然语言问题
	Context  string `json:"context"`  // 额外上下文（如漏洞类型/行业）
}

// ComplianceAnswer 合规问答结果。
type ComplianceAnswer struct {
	Answer     string      `json:"answer"`
	References []Reference `json:"references"`
	Mappings   []Mapping   `json:"mappings,omitempty"`
}

// Reference 合规引用。
type Reference struct {
	Framework string `json:"framework"` // 等保2.0/ISO27001/GDPR/PCI-DSS
	Clause    string `json:"clause"`    // 条款编号
	Title     string `json:"title"`     // 条款标题
	Excerpt   string `json:"excerpt"`   // 条款摘要
}

// Mapping 漏洞-合规映射。
type Mapping struct {
	VulnType    string `json:"vuln_type"`
	Framework   string `json:"framework"`
	Clause      string `json:"clause"`
	Requirement string `json:"requirement"`
	Impact      string `json:"impact"`      // 对合规的影响
	Remediation string `json:"remediation"` // 整改建议
}

// VulnComplianceRequest 漏洞合规映射请求。
type VulnComplianceRequest struct {
	VulnType   string   `json:"vuln_type"`
	Severity   string   `json:"severity"`
	Target     string   `json:"target"`
	Industry   string   `json:"industry"`             // 行业
	Frameworks []string `json:"frameworks,omitempty"` // 限定框架
}

// Service AI 合规知识服务。
type Service struct {
	ai    ai.Service
	model string
	rag   *ComplianceRAG
}

// NewService 创建 AI 合规知识服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{
		ai:    aiSvc,
		model: model,
		rag:   NewComplianceRAG(),
	}
}

// Ask 合规知识问答。
func (s *Service) Ask(ctx context.Context, query *ComplianceQuery) (*ComplianceAnswer, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	relatedClauses := s.rag.Search(query.Question, 5)
	prompt := buildCompliancePrompt(query, relatedClauses)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: complianceSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM compliance query failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseComplianceAnswer(resp.Choices[0].Message.Content)
}

// MapVulnToCompliance 将漏洞映射到合规条款。
func (s *Service) MapVulnToCompliance(ctx context.Context, req *VulnComplianceRequest) ([]Mapping, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	relatedClauses := s.rag.SearchByVulnType(req.VulnType, 8)
	prompt := buildMappingPrompt(req, relatedClauses)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: mappingSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM compliance mapping failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseMappingResponse(resp.Choices[0].Message.Content)
}

const complianceSystemPrompt = `你是一位资深安全合规顾问，精通：
- 等保2.0（GB/T 22239-2019）
- ISO/IEC 27001:2022
- GDPR（通用数据保护条例）
- PCI DSS 4.0
- 网络安全法

你的任务是回答安全合规相关的问题，引用具体条款，给出专业建议。

请以 JSON 格式返回：
{"answer":"回答内容","references":[{"framework":"","clause":"","title":"","excerpt":""}],"mappings":[]}`

const mappingSystemPrompt = `你是安全合规专家，负责将漏洞映射到合规条款。

对于给定的漏洞类型和行业背景，找出所有相关的合规条款，说明影响和整改要求。

请以 JSON 数组格式返回：
[{"vuln_type":"","framework":"","clause":"","requirement":"","impact":"","remediation":""}]`

func buildCompliancePrompt(query *ComplianceQuery, clauses []ClauseEntry) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 问题:\n%s\n\n", query.Question))
	if query.Context != "" {
		sb.WriteString(fmt.Sprintf("## 上下文:\n%s\n\n", query.Context))
	}
	if len(clauses) > 0 {
		sb.WriteString("## 参考条款（RAG检索结果）:\n")
		for _, c := range clauses {
			sb.WriteString(fmt.Sprintf("- [%s] %s: %s — %s\n", c.Framework, c.Clause, c.Title, c.Summary))
		}
	}
	return sb.String()
}

func buildMappingPrompt(req *VulnComplianceRequest, clauses []ClauseEntry) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 漏洞类型: %s\n", req.VulnType))
	sb.WriteString(fmt.Sprintf("## 严重级别: %s\n", req.Severity))
	if req.Industry != "" {
		sb.WriteString(fmt.Sprintf("## 行业: %s\n", req.Industry))
	}
	if len(req.Frameworks) > 0 {
		sb.WriteString(fmt.Sprintf("## 限定框架: %s\n", strings.Join(req.Frameworks, ", ")))
	}
	if len(clauses) > 0 {
		sb.WriteString("\n## 参考条款:\n")
		for _, c := range clauses {
			sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", c.Framework, c.Clause, c.Title))
		}
	}
	sb.WriteString("\n请将此漏洞映射到相关合规条款。")
	return sb.String()
}

func parseComplianceAnswer(content string) (*ComplianceAnswer, error) {
	content = extractJSON(content)
	var result ComplianceAnswer
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse compliance answer: %w", err)
	}
	return &result, nil
}

func parseMappingResponse(content string) ([]Mapping, error) {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
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
		content = strings.Join(jsonLines, "\n")
	}
	// handle both array [...] and object {mappings: [...]}
	start := strings.Index(content, "[")
	end := strings.LastIndex(content, "]")
	if start >= 0 && end > start {
		content = content[start : end+1]
	}
	var results []Mapping
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		return nil, fmt.Errorf("parse mapping response: %w", err)
	}
	return results, nil
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
