// Package aiverify 提供 LLM 驱动的智能漏洞验证能力。
//
// 在传统规则匹配发现疑似漏洞后，通过 LLM 分析请求/响应差异，
// 判断 payload 是否真正触发了漏洞，显著降低误报率。
package aiverify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// VerifyRequest 漏洞验证请求。
type VerifyRequest struct {
	VulnType   string `json:"vuln_type"`   // sqli/xss/ssrf/cmdi/lfi/ssti/xxe
	Target     string `json:"target"`      // 目标 URL
	Payload    string `json:"payload"`     // 使用的 payload
	BaseReq    string `json:"base_req"`    // 基准请求（无 payload）
	BaseResp   string `json:"base_resp"`   // 基准响应
	AttackReq  string `json:"attack_req"`  // 攻击请求（含 payload）
	AttackResp string `json:"attack_resp"` // 攻击响应
	WAFName    string `json:"waf_name,omitempty"`
	Extra      string `json:"extra,omitempty"` // 额外上下文（如 OOB callback 信息）
}

// VerifyResult 验证结果。
type VerifyResult struct {
	IsVulnerable bool   `json:"is_vulnerable"`
	Confidence   int    `json:"confidence"` // 0-100
	Reasoning    string `json:"reasoning"`
	FalseReason  string `json:"false_reason,omitempty"` // 若判定为误报，说明原因
	Suggestion   string `json:"suggestion,omitempty"`   // 进一步验证建议
}

// Service AI 漏洞验证服务。
type Service struct {
	ai    ai.Service
	model string
}

// NewService 创建 AI 验证服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{ai: aiSvc, model: model}
}

// Verify 通过 LLM 分析请求/响应差异，判断漏洞是否真实可利用。
func (s *Service) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResult, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildVerifyPrompt(req)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: verifySystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.1,
		MaxTokens:   512,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM verify request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseVerifyResponse(resp.Choices[0].Message.Content)
}

// BatchVerify 批量验证多个疑似漏洞。
func (s *Service) BatchVerify(ctx context.Context, requests []*VerifyRequest) ([]*VerifyResult, error) {
	results := make([]*VerifyResult, len(requests))
	for i, req := range requests {
		result, err := s.Verify(ctx, req)
		if err != nil {
			results[i] = &VerifyResult{
				IsVulnerable: true, // 验证失败时保守保留
				Confidence:   50,
				Reasoning:    fmt.Sprintf("AI verification failed: %v", err),
			}
			continue
		}
		results[i] = result
	}
	return results, nil
}

const verifySystemPrompt = `你是一位资深渗透测试工程师，专精于漏洞验证分析。

你的任务是分析给定的 HTTP 请求/响应对，判断安全扫描器发现的漏洞是否真实可利用。

分析要点：
1. 比较基准响应和攻击响应的差异
2. 判断 payload 是否真正被执行/解析
3. 识别常见误报模式：
   - 响应中包含 payload 但仅仅是反射（未执行）
   - 状态码/响应差异是由其他原因导致（如时间、随机性）
   - WAF 拦截导致的错误页面
   - 通用错误页面而非真实的注入错误
4. 对于 SQL 注入，关注：
   - 是否有数据库错误信息（区分通用错误 vs SQL 语法错误）
   - UNION 注入列数是否匹配
   - 盲注的时间差异是否稳定
5. 对于 XSS，关注：
   - payload 是否在 DOM 中可执行的位置
   - 是否被编码/转义处理
   - Content-Type 是否支持 HTML 渲染
6. 对于命令注入，关注：
   - 响应中是否有命令执行结果
   - 时间差异是否符合 sleep 命令预期

请以 JSON 格式返回：
{"is_vulnerable":true/false,"confidence":0-100,"reasoning":"分析过程","false_reason":"误报原因(如果是误报)","suggestion":"进一步验证建议"}`

func buildVerifyPrompt(req *VerifyRequest) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 漏洞类型: %s\n", req.VulnType))
	sb.WriteString(fmt.Sprintf("## 目标: %s\n", req.Target))
	sb.WriteString(fmt.Sprintf("## 使用的 Payload: %s\n\n", req.Payload))

	if req.WAFName != "" {
		sb.WriteString(fmt.Sprintf("## WAF: %s\n\n", req.WAFName))
	}

	sb.WriteString("## 基准请求（无 payload）:\n")
	sb.WriteString(truncate(req.BaseReq, 1000))
	sb.WriteString("\n\n## 基准响应:\n")
	sb.WriteString(truncate(req.BaseResp, 1500))
	sb.WriteString("\n\n## 攻击请求（含 payload）:\n")
	sb.WriteString(truncate(req.AttackReq, 1000))
	sb.WriteString("\n\n## 攻击响应:\n")
	sb.WriteString(truncate(req.AttackResp, 1500))

	if req.Extra != "" {
		sb.WriteString("\n\n## 额外信息:\n")
		sb.WriteString(req.Extra)
	}

	sb.WriteString("\n\n请分析此漏洞是否真实可利用。")
	return sb.String()
}

func parseVerifyResponse(content string) (*VerifyResult, error) {
	content = extractJSONObject(content)
	var result VerifyResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse verify response: %w", err)
	}
	return &result, nil
}

func extractJSONObject(s string) string {
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

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "\n...(truncated)"
	}
	return s
}
