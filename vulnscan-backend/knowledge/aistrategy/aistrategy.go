// Package aistrategy 提供 LLM 驱动的上下文感知扫描策略推荐。
//
// 根据目标的行业、技术栈、暴露面等信息，智能推荐最优的扫描模板和模块组合，
// 避免盲目全量扫描导致的效率低下和误报。
package aistrategy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// TargetProfile 目标画像。
type TargetProfile struct {
	Domain      string   `json:"domain"`
	Industry    string   `json:"industry,omitempty"`    // 行业（金融/政务/医疗/电商/教育）
	TechStack   []string `json:"tech_stack,omitempty"`  // 技术栈
	WAF         string   `json:"waf,omitempty"`         // WAF 信息
	OS          string   `json:"os,omitempty"`          // 操作系统
	Ports       []int    `json:"ports,omitempty"`       // 开放端口
	Services    []string `json:"services,omitempty"`    // 运行服务
	Exposure    string   `json:"exposure,omitempty"`    // 暴露面（internet/intranet/dmz）
	Sensitivity string   `json:"sensitivity,omitempty"` // 敏感度（high/medium/low）
}

// ScanStrategy 扫描策略推荐结果。
type ScanStrategy struct {
	RecommendedModules []ModuleRecommendation `json:"recommended_modules"`
	ScanIntensity      string                 `json:"scan_intensity"` // fast/normal/deep
	SafeMode           string                 `json:"safe_mode"`      // strict/standard/off
	Priority           string                 `json:"priority"`       // 扫描重点说明
	Reasoning          string                 `json:"reasoning"`      // 推荐理由
	EstimatedDuration  string                 `json:"estimated_duration"`
	Warnings           []string               `json:"warnings"` // 注意事项
}

// ModuleRecommendation 模块推荐。
type ModuleRecommendation struct {
	ModuleID string `json:"module_id"`
	Priority int    `json:"priority"` // 1-5，5最高
	Reason   string `json:"reason"`
	Config   string `json:"config,omitempty"` // 推荐的模块配置
}

// Service AI 策略推荐服务。
type Service struct {
	ai    ai.Service
	model string
}

// NewService 创建 AI 策略推荐服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{ai: aiSvc, model: model}
}

// RecommendStrategy 根据目标画像推荐扫描策略。
func (s *Service) RecommendStrategy(ctx context.Context, profile *TargetProfile) (*ScanStrategy, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildStrategyPrompt(profile)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: strategySystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM strategy recommendation failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseStrategyResponse(resp.Choices[0].Message.Content)
}

const strategySystemPrompt = `你是一位资深安全测试顾问，精通漏洞扫描策略规划。

你的任务是根据目标的行业、技术栈、暴露面等信息，推荐最优的扫描策略。

可用的扫描模块包括：
- netscan: 网络探测（端口扫描/存活检测）
- dns: DNS 侦查（子域名枚举/AXFR/DNS记录）
- fingerprint: 指纹识别（Web指纹/技术检测/WAF检测）
- assetinfo: 资产信息（真实IP/公司信息/证书检查）
- infoleak: 信息泄露（目录扫描/Git泄露/JS分析）
- webcrawl: Web 爬虫（认证爬取/JS渲染）
- sqli: SQL 注入
- xss: XSS 跨站脚本
- cmdi: 命令注入
- ssrf: SSRF 服务端请求伪造
- lfi: 本地文件包含
- injection: 综合注入（SSTI/XXE/NoSQLi）
- credential: 凭据安全（弱口令/未授权访问）
- api_security: API 安全（API发现/GraphQL）
- web_misc: Web杂项（CORS/开放重定向/安全头）
- advancedvuln: 高级漏洞（Nuclei模板扫描）

策略规划原则：
1. 金融/政务系统：高安全模式，避免破坏性测试
2. 有 WAF 的目标：启用 payload 变体生成
3. IoT/网络设备：重点弱口令和已知漏洞
4. Java 技术栈：重点检测反序列化/SSTI/JNDI
5. PHP 技术栈：重点检测文件包含/SQL注入
6. 内网系统：可适当放宽强度

请以 JSON 格式返回：
{"recommended_modules":[{"module_id":"","priority":1-5,"reason":"","config":""}],"scan_intensity":"fast|normal|deep","safe_mode":"strict|standard|off","priority":"扫描重点","reasoning":"推荐理由","estimated_duration":"预估耗时","warnings":["注意事项"]}`

func buildStrategyPrompt(profile *TargetProfile) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 目标域名: %s\n", profile.Domain))
	if profile.Industry != "" {
		sb.WriteString(fmt.Sprintf("## 行业: %s\n", profile.Industry))
	}
	if len(profile.TechStack) > 0 {
		sb.WriteString(fmt.Sprintf("## 技术栈: %s\n", strings.Join(profile.TechStack, ", ")))
	}
	if profile.WAF != "" {
		sb.WriteString(fmt.Sprintf("## WAF: %s\n", profile.WAF))
	}
	if profile.OS != "" {
		sb.WriteString(fmt.Sprintf("## 操作系统: %s\n", profile.OS))
	}
	if len(profile.Ports) > 0 {
		ports := make([]string, len(profile.Ports))
		for i, p := range profile.Ports {
			ports[i] = fmt.Sprintf("%d", p)
		}
		sb.WriteString(fmt.Sprintf("## 开放端口: %s\n", strings.Join(ports, ", ")))
	}
	if len(profile.Services) > 0 {
		sb.WriteString(fmt.Sprintf("## 运行服务: %s\n", strings.Join(profile.Services, ", ")))
	}
	if profile.Exposure != "" {
		sb.WriteString(fmt.Sprintf("## 暴露面: %s\n", profile.Exposure))
	}
	if profile.Sensitivity != "" {
		sb.WriteString(fmt.Sprintf("## 敏感度: %s\n", profile.Sensitivity))
	}
	sb.WriteString("\n请根据以上信息推荐最优的扫描策略。")
	return sb.String()
}

func parseStrategyResponse(content string) (*ScanStrategy, error) {
	content = extractJSON(content)
	var result ScanStrategy
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse strategy response: %w", err)
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
