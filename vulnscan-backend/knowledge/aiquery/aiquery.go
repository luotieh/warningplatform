// Package aiquery 提供 LLM 驱动的自然语言安全查询能力 (NL2Query)。
//
// 用户使用自然语言提问，如"哪些资产有高危漏洞且暴露在公网？"，
// LLM 将其转换为结构化查询条件，查询资产/漏洞数据库。
package aiquery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// QueryCondition 结构化查询条件。
type QueryCondition struct {
	Entity      string       `json:"entity"` // asset/vuln/finding/task
	Filters     []Filter     `json:"filters"`
	OrderBy     string       `json:"order_by,omitempty"`
	OrderDir    string       `json:"order_dir,omitempty"` // asc/desc
	Limit       int          `json:"limit,omitempty"`
	Aggregation *Aggregation `json:"aggregation,omitempty"`
	Explanation string       `json:"explanation"` // LLM 对查询理解的说明
}

// Filter 过滤条件。
type Filter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq/ne/gt/lt/gte/lte/contains/in/not_in/is_null/not_null
	Value    interface{} `json:"value"`
}

// Aggregation 聚合操作。
type Aggregation struct {
	Type    string `json:"type"` // count/sum/avg/group_by
	Field   string `json:"field"`
	GroupBy string `json:"group_by,omitempty"`
}

// QueryResult 查询结果（由调用方填充实际数据后返回）。
type QueryResult struct {
	Query     *QueryCondition `json:"query"`
	NLSummary string          `json:"nl_summary"` // 自然语言总结
	Count     int             `json:"count"`
	Data      interface{}     `json:"data,omitempty"`
}

// Service AI 查询服务。
type Service struct {
	ai    ai.Service
	model string
}

// NewService 创建 AI 查询服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{ai: aiSvc, model: model}
}

// ParseQuery 将自然语言问题转换为结构化查询条件。
func (s *Service) ParseQuery(ctx context.Context, question string) (*QueryCondition, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: querySystemPrompt},
			{Role: "user", Content: question},
		},
		Temperature: 0.1,
		MaxTokens:   512,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM query parse failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseQueryResponse(resp.Choices[0].Message.Content)
}

// SummarizeResults 对查询结果生成自然语言总结。
func (s *Service) SummarizeResults(ctx context.Context, question string, data interface{}, count int) (string, error) {
	if s.ai == nil {
		return "", fmt.Errorf("AI service not configured")
	}

	dataJSON, _ := json.Marshal(data)
	dataStr := string(dataJSON)
	if len(dataStr) > 3000 {
		dataStr = dataStr[:3000] + "...(truncated)"
	}

	prompt := fmt.Sprintf("用户问题: %s\n\n查询结果 (共%d条):\n%s\n\n请用简洁的自然语言总结查询结果，回答用户的问题。直接回复总结文本即可。",
		question, count, dataStr)

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: "你是安全运营助手，负责用简洁专业的语言总结安全查询结果。"},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   256,
	})
	if err != nil {
		return "", err
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}

	return strings.TrimSpace(resp.Choices[0].Message.Content), nil
}

const querySystemPrompt = `你是一位安全数据分析助手，负责将自然语言问题转换为结构化查询。

数据库实体和字段：

## asset (资产表)
- id, domain, ip, port, protocol, title, status
- severity_level (资产风险等级: critical/high/medium/low)
- is_public (是否公网暴露: true/false)
- os, product, version, tech_stack
- company, department
- created_at, updated_at, last_scan_time

## vuln (漏洞表) 
- id, asset_id, title, type, severity (critical/high/medium/low/info)
- status (open/fixed/ignored/false_positive)
- cve_id, target, port
- module_id, confidence
- created_at, fixed_at

## finding (扫描发现)
- id, task_id, asset_id, module_id, type, category
- target, port, severity, confidence
- title, description, evidence

## task (扫描任务)
- id, name, status (pending/running/completed/failed)
- target_count, finding_count
- started_at, completed_at

运算符说明：
- eq: 等于
- ne: 不等于  
- gt/lt/gte/lte: 大于/小于/大于等于/小于等于
- contains: 包含
- in: 在列表中
- not_in: 不在列表中
- is_null/not_null: 为空/不为空

请将用户的自然语言问题转为 JSON：
{"entity":"","filters":[{"field":"","operator":"","value":""}],"order_by":"","order_dir":"","limit":0,"aggregation":null,"explanation":""}

示例：
- "有多少高危漏洞?" → {"entity":"vuln","filters":[{"field":"severity","operator":"eq","value":"high"}],"aggregation":{"type":"count","field":"id"},"explanation":"统计严重级别为 high 的漏洞数量"}
- "公网暴露的资产中有哪些存在严重漏洞?" → {"entity":"asset","filters":[{"field":"is_public","operator":"eq","value":true},{"field":"severity_level","operator":"eq","value":"critical"}],"explanation":"查找公网可访问且存在严重漏洞的资产"}`

func parseQueryResponse(content string) (*QueryCondition, error) {
	content = extractJSON(content)
	var result QueryCondition
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse query response: %w", err)
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
