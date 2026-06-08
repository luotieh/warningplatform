// Package aifingerprint 提供 LLM 驱动的智能指纹识别能力。
//
// 两大核心能力：
//  1. AI 自动生成设备指纹：从 Banner、HTTP 头、网页源码中自动提炼软硬件指纹，
//     识别从未入库的新型设备、自研中间件。
//  2. NLP 跨实体关联隐藏资产：通过语义相似度分析企业主体、业务描述，
//     发现并购遗留资产、影子 IT、关联子域名。
package aifingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// FingerprintResult LLM 分析产出的指纹结果。
type FingerprintResult struct {
	Product    string `json:"product"`
	Version    string `json:"version"`
	Vendor     string `json:"vendor"`
	Category   string `json:"category"` // web_server/middleware/database/iot/network_device/custom
	OS         string `json:"os,omitempty"`
	Language   string `json:"language,omitempty"`
	Framework  string `json:"framework,omitempty"`
	Confidence int    `json:"confidence"` // 0-100
	Evidence   string `json:"evidence"`
}

// AssetRelation NLP 发现的跨实体关联关系。
type AssetRelation struct {
	SourceHost  string  `json:"source_host"`
	RelatedHost string  `json:"related_host"`
	RelType     string  `json:"rel_type"` // subsidiary/shadow_it/takeover_candidate/shared_infra
	Confidence  float64 `json:"confidence"`
	Reason      string  `json:"reason"`
}

// Service AI 指纹识别与关联分析服务。
type Service struct {
	ai    ai.Service
	model string
}

// NewService 创建 AI 指纹识别服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{ai: aiSvc, model: model}
}

// AnalyzeFingerprint 通过 LLM 分析原始数据，自动生成指纹。
// rawData 可以是 Banner 文本、HTTP 响应头、网页 HTML 片段等。
func (s *Service) AnalyzeFingerprint(ctx context.Context, rawData map[string]string) ([]FingerprintResult, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildFingerprintPrompt(rawData)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: fingerprintSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.1,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	content := resp.Choices[0].Message.Content
	return parseFingerprintResponse(content)
}

// AnalyzeRelations 通过 NLP 语义分析发现跨实体关联。
// entities 是已知的资产/域名/企业信息集合。
func (s *Service) AnalyzeRelations(ctx context.Context, entities []EntityInfo) ([]AssetRelation, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}
	if len(entities) < 2 {
		return nil, nil
	}

	prompt := buildRelationPrompt(entities)

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: relationSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
		MaxTokens:   2048,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	content := resp.Choices[0].Message.Content
	return parseRelationResponse(content)
}

// EntityInfo 用于关联分析的实体信息。
type EntityInfo struct {
	Host        string `json:"host"`
	Domain      string `json:"domain,omitempty"`
	IP          string `json:"ip,omitempty"`
	Title       string `json:"title,omitempty"`
	Company     string `json:"company,omitempty"`
	ICP         string `json:"icp,omitempty"`
	Description string `json:"description,omitempty"`
	TLSOrg      string `json:"tls_org,omitempty"`
	Whois       string `json:"whois,omitempty"`
}

const fingerprintSystemPrompt = `你是一位资深安全工程师，专精于设备指纹识别。
你的任务是从给定的原始网络数据（Banner、HTTP头、HTML片段等）中精确识别出：
- 软件产品名称和版本
- 硬件设备型号
- 操作系统
- 编程语言/框架
- 厂商信息

注意事项：
1. 只输出你有把握的结果，不确定的标注低置信度
2. 能识别自研/非标准软件，通过代码特征、命名规范推断
3. 关注国产化设备（达梦、人大金仓、麒麟、统信等）

请以 JSON 数组格式回复，每个元素包含:
{"product":"","version":"","vendor":"","category":"","os":"","language":"","framework":"","confidence":0,"evidence":""}

如果无法识别任何指纹，返回空数组 []。`

const relationSystemPrompt = `你是一位安全分析师，专精于资产关联分析。
你的任务是从给定的多个资产实体信息中，发现它们之间的隐藏关联关系：
- 同一企业主体的不同资产（包括并购/子公司）
- 影子 IT（未备案但属于同一组织的资产）
- 可能被接管的子域名
- 共享基础设施（同一 IP 段/云账号/CDN）

分析维度：
1. 域名/子域名命名规律
2. ICP 备案主体关联
3. TLS 证书组织字段
4. Whois 注册信息
5. 网页标题/描述语义相似度

请以 JSON 数组格式回复，每个元素包含:
{"source_host":"","related_host":"","rel_type":"","confidence":0.0,"reason":""}

rel_type 可选值: subsidiary, shadow_it, takeover_candidate, shared_infra
如果没有发现关联，返回空数组 []。`

func buildFingerprintPrompt(rawData map[string]string) string {
	var sb strings.Builder
	sb.WriteString("请分析以下原始网络数据，提取设备/软件指纹：\n\n")
	for key, val := range rawData {
		if len(val) > 2000 {
			val = val[:2000] + "...(truncated)"
		}
		sb.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", key, val))
	}
	return sb.String()
}

func buildRelationPrompt(entities []EntityInfo) string {
	var sb strings.Builder
	sb.WriteString("请分析以下资产实体之间的潜在关联关系：\n\n")
	for i, e := range entities {
		sb.WriteString(fmt.Sprintf("实体 %d:\n", i+1))
		if e.Host != "" {
			sb.WriteString(fmt.Sprintf("  主机: %s\n", e.Host))
		}
		if e.Domain != "" {
			sb.WriteString(fmt.Sprintf("  域名: %s\n", e.Domain))
		}
		if e.IP != "" {
			sb.WriteString(fmt.Sprintf("  IP: %s\n", e.IP))
		}
		if e.Title != "" {
			sb.WriteString(fmt.Sprintf("  标题: %s\n", e.Title))
		}
		if e.Company != "" {
			sb.WriteString(fmt.Sprintf("  企业: %s\n", e.Company))
		}
		if e.ICP != "" {
			sb.WriteString(fmt.Sprintf("  ICP: %s\n", e.ICP))
		}
		if e.TLSOrg != "" {
			sb.WriteString(fmt.Sprintf("  证书组织: %s\n", e.TLSOrg))
		}
		if e.Whois != "" {
			sb.WriteString(fmt.Sprintf("  Whois: %s\n", e.Whois))
		}
		if e.Description != "" {
			sb.WriteString(fmt.Sprintf("  描述: %s\n", e.Description))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func parseFingerprintResponse(content string) ([]FingerprintResult, error) {
	content = extractJSON(content)
	var results []FingerprintResult
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		slog.Warn("[AIFingerprint] JSON 解析失败，尝试容错", "error", err, "content", content[:min(200, len(content))])
		return nil, fmt.Errorf("parse LLM response: %w", err)
	}
	return results, nil
}

func parseRelationResponse(content string) ([]AssetRelation, error) {
	content = extractJSON(content)
	var results []AssetRelation
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		slog.Warn("[AIRelation] JSON 解析失败", "error", err)
		return nil, fmt.Errorf("parse LLM response: %w", err)
	}
	return results, nil
}

// extractJSON 从 LLM 响应中提取 JSON 数组（处理 markdown code block 包裹的情况）。
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
	// 找到第一个 [ 和最后一个 ]
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
