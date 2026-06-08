// Package aicrawl 提供 LLM 驱动的智能爬虫决策能力。
//
// 当爬虫遇到复杂表单、JS 交互、验证码等场景时，
// 通过 LLM 理解页面语义，决定最优的填充策略和交互路径。
package aicrawl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// FormAnalysisRequest 表单分析请求。
type FormAnalysisRequest struct {
	PageURL     string `json:"page_url"`
	PageTitle   string `json:"page_title"`
	FormHTML    string `json:"form_html"`    // 表单 HTML 片段
	PageContext string `json:"page_context"` // 页面上下文文本
}

// FormFillStrategy 表单填充策略。
type FormFillStrategy struct {
	Fields []FieldStrategy `json:"fields"`
	Action string          `json:"action"` // submit_normal/skip/need_auth/need_captcha
	Notes  string          `json:"notes"`
}

// FieldStrategy 单个字段的填充策略。
type FieldStrategy struct {
	FieldName   string `json:"field_name"`
	FieldType   string `json:"field_type"`
	FillValue   string `json:"fill_value"`
	FillPurpose string `json:"fill_purpose"` // normal_test/boundary_test/injection_test/auth
}

// InteractionRequest 页面交互决策请求。
type InteractionRequest struct {
	PageURL   string   `json:"page_url"`
	PageHTML  string   `json:"page_html"` // 页面 HTML 片段（截取关键区域）
	Buttons   []string `json:"buttons"`   // 页面上可见按钮文本
	Links     []string `json:"links"`     // 页面链接
	JSEvents  []string `json:"js_events"` // 检测到的 JS 事件
	Objective string   `json:"objective"` // 爬取目标（discover_api/find_auth/explore_all）
}

// InteractionPlan 交互计划。
type InteractionPlan struct {
	Steps  []InteractionStep `json:"steps"`
	Skip   bool              `json:"skip"`
	Reason string            `json:"reason,omitempty"`
}

// InteractionStep 单个交互步骤。
type InteractionStep struct {
	Action   string `json:"action"`   // click/input/scroll/wait/hover
	Selector string `json:"selector"` // CSS 选择器
	Value    string `json:"value,omitempty"`
	Reason   string `json:"reason"`
}

// Service AI 爬虫决策服务。
type Service struct {
	ai    ai.Service
	model string
}

// NewService 创建 AI 爬虫决策服务。
func NewService(aiSvc ai.Service, model string) *Service {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Service{ai: aiSvc, model: model}
}

// AnalyzeForm 分析表单并生成填充策略。
func (s *Service) AnalyzeForm(ctx context.Context, req *FormAnalysisRequest) (*FormFillStrategy, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildFormPrompt(req)

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: formSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
		MaxTokens:   512,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM form analysis failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseFormResponse(resp.Choices[0].Message.Content)
}

// PlanInteraction 规划页面交互路径。
func (s *Service) PlanInteraction(ctx context.Context, req *InteractionRequest) (*InteractionPlan, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	prompt := buildInteractionPrompt(req)

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: interactionSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   512,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM interaction plan failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	return parseInteractionResponse(resp.Choices[0].Message.Content)
}

const formSystemPrompt = `你是一位 Web 安全测试专家，精通表单交互和安全测试。

你的任务是分析 HTML 表单，为安全爬虫提供智能填充策略。

分析要点：
1. 理解表单用途（登录/注册/搜索/数据提交/支付等）
2. 为每个字段推断合适的测试值
3. 区分必填字段和可选字段
4. 识别验证码、文件上传等特殊字段
5. 判断是否需要认证才能提交

填充策略原则：
- 使用看起来合理的测试数据（不要用明显的 test/admin）
- Email 字段用 user@example.com 格式
- 电话用合规格式 13800138000
- 数字字段用边界值
- 对于危险操作（删除/支付）建议跳过

请以 JSON 格式返回：
{"fields":[{"field_name":"","field_type":"","fill_value":"","fill_purpose":""}],"action":"submit_normal|skip|need_auth|need_captcha","notes":""}`

const interactionSystemPrompt = `你是一位 Web 安全测试专家，精通页面自动化交互。

你的任务是分析页面结构，规划安全爬虫的最优交互路径，以发现更多 API 端点和功能页面。

分析要点：
1. 识别值得探索的按钮/链接（可能触发 AJAX 请求的）
2. 识别动态加载内容的触发方式
3. 规避危险操作（删除/退出/支付）
4. 优先探索可能暴露 API 或隐藏功能的交互

请以 JSON 格式返回：
{"steps":[{"action":"click|input|scroll|wait|hover","selector":"CSS选择器","value":"输入值(可选)","reason":"原因"}],"skip":false,"reason":""}`

func buildFormPrompt(req *FormAnalysisRequest) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 页面 URL: %s\n", req.PageURL))
	if req.PageTitle != "" {
		sb.WriteString(fmt.Sprintf("## 页面标题: %s\n", req.PageTitle))
	}
	sb.WriteString("\n## 表单 HTML:\n")
	html := req.FormHTML
	if len(html) > 3000 {
		html = html[:3000] + "...(truncated)"
	}
	sb.WriteString(html)
	if req.PageContext != "" {
		sb.WriteString("\n\n## 页面上下文:\n")
		ctx := req.PageContext
		if len(ctx) > 500 {
			ctx = ctx[:500]
		}
		sb.WriteString(ctx)
	}
	sb.WriteString("\n\n请分析此表单并给出填充策略。")
	return sb.String()
}

func buildInteractionPrompt(req *InteractionRequest) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## 页面 URL: %s\n", req.PageURL))
	sb.WriteString(fmt.Sprintf("## 爬取目标: %s\n", req.Objective))

	if len(req.Buttons) > 0 {
		sb.WriteString(fmt.Sprintf("\n## 可见按钮: %s\n", strings.Join(req.Buttons, ", ")))
	}
	if len(req.Links) > 0 {
		links := req.Links
		if len(links) > 20 {
			links = links[:20]
		}
		sb.WriteString(fmt.Sprintf("\n## 链接: %s\n", strings.Join(links, ", ")))
	}
	if len(req.JSEvents) > 0 {
		sb.WriteString(fmt.Sprintf("\n## JS 事件: %s\n", strings.Join(req.JSEvents, ", ")))
	}

	html := req.PageHTML
	if len(html) > 2000 {
		html = html[:2000] + "...(truncated)"
	}
	sb.WriteString("\n## 页面 HTML 片段:\n")
	sb.WriteString(html)
	sb.WriteString("\n\n请规划最优交互路径。")
	return sb.String()
}

func parseFormResponse(content string) (*FormFillStrategy, error) {
	content = extractJSON(content)
	var result FormFillStrategy
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse form response: %w", err)
	}
	return &result, nil
}

func parseInteractionResponse(content string) (*InteractionPlan, error) {
	content = extractJSON(content)
	var result InteractionPlan
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse interaction response: %w", err)
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
