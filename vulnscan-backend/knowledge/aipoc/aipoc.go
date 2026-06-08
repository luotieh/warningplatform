// Package aipoc 提供 LLM 驱动的 POC 自动编写能力。
//
// 给定 CVE 描述和目标特征，LLM 自动生成 Nuclei 兼容的检测模板，
// 结合已有 POC 库作为 few-shot 参考，生成质量更高的 POC。
package aipoc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// GenerateRequest POC 生成请求。
type GenerateRequest struct {
	CVE          string `json:"cve"`           // CVE 编号
	Title        string `json:"title"`         // 漏洞标题
	Description  string `json:"description"`   // 漏洞描述
	Severity     string `json:"severity"`      // 严重级别
	AffectedApp  string `json:"affected_app"`  // 受影响应用
	Version      string `json:"version"`       // 受影响版本
	VulnType     string `json:"vuln_type"`     // 漏洞类型 (rce/sqli/xss/lfi/ssrf/auth_bypass 等)
	Reference    string `json:"reference"`     // 参考链接
	ExistingPocs string `json:"existing_pocs"` // 已有类似 POC（作为 few-shot 参考）
}

// GenerateResult POC 生成结果。
type GenerateResult struct {
	PocYAML     string `json:"poc_yaml"`    // 生成的 Nuclei 模板 YAML
	Explanation string `json:"explanation"` // POC 工作原理说明
	TestGuide   string `json:"test_guide"`  // 测试指南
	Confidence  int    `json:"confidence"`  // 可信度 0-100
	Warnings    string `json:"warnings"`    // 注意事项/局限性
}

// Service AI POC 生成服务。
type Service struct {
	ai    ai.Service
	model string
}

// NewService 创建 AI POC 生成服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{ai: aiSvc, model: model}
}

// Generate 根据 CVE 信息生成 Nuclei 检测模板。
func (s *Service) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResult, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildPocPrompt(req)

	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: pocSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   2048,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM POC generation failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parsePocResponse(resp.Choices[0].Message.Content)
}

// Improve 对现有 POC 进行优化。
func (s *Service) Improve(ctx context.Context, existingPoc string, feedback string) (*GenerateResult, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := fmt.Sprintf("## 现有 POC:\n```yaml\n%s\n```\n\n## 优化需求:\n%s\n\n请优化此 POC。",
		existingPoc, feedback)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: pocSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   2048,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM POC improvement failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parsePocResponse(resp.Choices[0].Message.Content)
}

const pocSystemPrompt = `你是一位资深安全研究员，精通漏洞 POC 编写和 Nuclei 模板语法。

你的任务是根据给定的 CVE 信息，生成高质量的 Nuclei 兼容检测模板。

Nuclei 模板要求：
1. 使用标准 Nuclei YAML 格式
2. 包含完整的 info 部分（id, name, author, severity, description, reference, tags）
3. 使用 http 协议的 requests 部分
4. matchers 要精确，避免误报
5. 优先使用无害检测方法（读取版本号、计算哈希、检测特征页面）
6. 如果需要多步检测，使用 flow/pipeline

安全原则：
- 不生成破坏性 POC（如删除文件、写入 webshell）
- 检测方法应该是安全的（读取而非写入）
- 对于 RCE 类漏洞，使用 sleep/dns-callback 等无害方式验证

请以 JSON 格式返回：
{"poc_yaml":"完整的Nuclei YAML模板","explanation":"POC工作原理","test_guide":"测试步骤","confidence":0-100,"warnings":"注意事项"}`

func buildPocPrompt(req *GenerateRequest) string {
	var sb strings.Builder
	if req.CVE != "" {
		sb.WriteString(fmt.Sprintf("## CVE: %s\n", req.CVE))
	}
	sb.WriteString(fmt.Sprintf("## 标题: %s\n", req.Title))
	sb.WriteString(fmt.Sprintf("## 严重级别: %s\n", req.Severity))
	sb.WriteString(fmt.Sprintf("## 漏洞类型: %s\n", req.VulnType))
	if req.AffectedApp != "" {
		sb.WriteString(fmt.Sprintf("## 受影响应用: %s\n", req.AffectedApp))
	}
	if req.Version != "" {
		sb.WriteString(fmt.Sprintf("## 受影响版本: %s\n", req.Version))
	}
	sb.WriteString(fmt.Sprintf("\n## 漏洞描述:\n%s\n", req.Description))
	if req.Reference != "" {
		sb.WriteString(fmt.Sprintf("\n## 参考:\n%s\n", req.Reference))
	}
	if req.ExistingPocs != "" {
		sb.WriteString(fmt.Sprintf("\n## 参考 POC（类似漏洞的已有模板）:\n```yaml\n%s\n```\n", req.ExistingPocs))
	}
	sb.WriteString("\n请生成 Nuclei 检测模板。")
	return sb.String()
}

func parsePocResponse(content string) (*GenerateResult, error) {
	content = extractJSON(content)
	var result GenerateResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse POC response: %w", err)
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
