// Package aipayload 提供 LLM 驱动的智能 Payload 生成能力。
//
// 根据 WAF 类型和已被拦截的 payload，动态生成绕过 WAF 的变体 payload，
// 解决传统字典有限、绕过能力不足的问题。
package aipayload

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// GenerateRequest Payload 生成请求。
type GenerateRequest struct {
	VulnType       string   `json:"vuln_type"`       // sqli/xss/cmdi/ssti/ssrf/lfi
	WAFName        string   `json:"waf_name"`        // 目标 WAF 名称
	BlockedPayload string   `json:"blocked_payload"` // 被拦截的原始 payload
	Context        string   `json:"context"`         // 注入上下文（URL参数/POST Body/Header/Cookie）
	TargetDB       string   `json:"target_db,omitempty"`
	TargetOS       string   `json:"target_os,omitempty"`
	Constraints    []string `json:"constraints,omitempty"` // 额外约束（如长度限制、字符黑名单）
}

// GenerateResult 生成结果。
type GenerateResult struct {
	Payloads []PayloadItem `json:"payloads"`
}

// PayloadItem 单个 payload 条目。
type PayloadItem struct {
	Payload    string `json:"payload"`
	Technique  string `json:"technique"`  // 绕过技术说明
	Confidence int    `json:"confidence"` // 预估成功率 0-100
}

// Service AI Payload 生成服务。
type Service struct {
	ai    ai.Service
	model string
}

// NewService 创建 AI Payload 生成服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{ai: aiSvc, model: model}
}

// Generate 生成绕过 WAF 的 Payload 变体。
func (s *Service) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResult, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildPayloadPrompt(req)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: payloadSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.7,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM payload generation failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parsePayloadResponse(resp.Choices[0].Message.Content)
}

// GenerateForSQLi 专门为 SQL 注入生成绕过 payload。
func (s *Service) GenerateForSQLi(ctx context.Context, wafName, blockedPayload, targetDB string) (*GenerateResult, error) {
	return s.Generate(ctx, &GenerateRequest{
		VulnType:       "sqli",
		WAFName:        wafName,
		BlockedPayload: blockedPayload,
		TargetDB:       targetDB,
	})
}

// GenerateForXSS 专门为 XSS 生成绕过 payload。
func (s *Service) GenerateForXSS(ctx context.Context, wafName, blockedPayload, injectContext string) (*GenerateResult, error) {
	return s.Generate(ctx, &GenerateRequest{
		VulnType:       "xss",
		WAFName:        wafName,
		BlockedPayload: blockedPayload,
		Context:        injectContext,
	})
}

const payloadSystemPrompt = `你是一位资深红队安全研究员，精通 WAF 绕过技术。

你的任务是根据给定的 WAF 类型和被拦截的 payload，生成能够绕过 WAF 检测的变体 payload。

绕过技术包括但不限于：
- 大小写混合 (MiXeD CaSe)
- 注释插入 (/**/、/*!*/、--、#)
- 编码变换 (URL编码、Unicode、HTML实体、十六进制)
- 空白符替代 (\t、\n、\r、%09、%0a)
- 等价函数替换 (CONCAT→CONCAT_WS, UNION→UNION%a0SELECT)
- 科学计数法/数学表达式
- 双写绕过 (SELSELECTECT)
- 参数污染 (HPP)
- 分块传输 (chunked encoding tricks)
- JSON/XML 封装
- 针对特定 WAF 的已知绕过

安全要求：
- 只生成用于安全测试的检测 payload
- 避免生成可能导致数据破坏的 payload (如 DROP TABLE)
- payload 应该以确认漏洞存在为目的（如读取版本号、计算表达式）

请以 JSON 格式返回：
{"payloads":[{"payload":"...","technique":"绕过技术说明","confidence":0-100}]}

生成 5-8 个不同技术路线的变体 payload。`

func buildPayloadPrompt(req *GenerateRequest) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 漏洞类型: %s\n", req.VulnType))
	sb.WriteString(fmt.Sprintf("## WAF: %s\n", req.WAFName))
	sb.WriteString(fmt.Sprintf("## 被拦截的 Payload: %s\n", req.BlockedPayload))

	if req.Context != "" {
		sb.WriteString(fmt.Sprintf("## 注入上下文: %s\n", req.Context))
	}
	if req.TargetDB != "" {
		sb.WriteString(fmt.Sprintf("## 目标数据库: %s\n", req.TargetDB))
	}
	if req.TargetOS != "" {
		sb.WriteString(fmt.Sprintf("## 目标操作系统: %s\n", req.TargetOS))
	}
	if len(req.Constraints) > 0 {
		sb.WriteString(fmt.Sprintf("## 约束条件: %s\n", strings.Join(req.Constraints, ", ")))
	}

	sb.WriteString("\n请生成绕过此 WAF 的变体 payload。")
	return sb.String()
}

func parsePayloadResponse(content string) (*GenerateResult, error) {
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
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		content = content[start : end+1]
	}

	var result GenerateResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse payload response: %w", err)
	}
	return &result, nil
}
