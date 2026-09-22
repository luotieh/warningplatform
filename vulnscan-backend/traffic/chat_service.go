package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	trafficconfig "vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/realtime"
	trafficservice "vulnscan-backend/traffic/internal/service"
)

type ChatService struct {
	core trafficservice.Services
}

func NewChatService(core trafficservice.Services) *ChatService {
	return &ChatService{core: core}
}

func (s *ChatService) UpdateLLM(settings trafficconfig.LLMSettings) {
	s.core.LLM.BaseURL = settings.BaseURL
	s.core.LLM.APIKey = settings.APIKey
	s.core.LLM.Model = settings.Model
	s.core.LLM.HTTP = &http.Client{Timeout: time.Duration(settings.TimeoutSeconds) * time.Second}
	s.core.LLM.MaxTokens = settings.MaxTokens
	s.core.LLM.DisableThinking = settings.DisableThinking
}

func (s *ChatService) Send(ctx context.Context, body map[string]any) (map[string]any, error) {
	eventID := stringValue(body["event_id"])
	message := strings.TrimSpace(stringValue(body["message"]))
	if eventID == "" || message == "" {
		return nil, errors.New("event_id和message不能为空")
	}
	event, ok := s.core.Store.GetEvent(eventID)
	if !ok {
		return nil, errors.New("事件不存在")
	}

	// Build before persisting the current question so it is not duplicated in history.
	evidenceContext, err := s.core.EvidenceContext(ctx, event)
	if err != nil {
		return nil, err
	}
	event.Context = evidenceContext
	prompt := s.engineerEventPrompt(event, message)
	userMessage, _ := s.core.Store.AddMessage(domain.Message{
		EventID:         eventID,
		MessageFrom:     domain.RoleUser,
		MessageType:     "user_message",
		MessageContent:  message,
		RoundID:         1,
		MessageCategory: "engineer_chat",
		SenderType:      "user",
		ChatSessionID:   stringValue(body["chat_session_id"]),
		UserID:          stringValue(body["user_id"]),
		UserNickname:    stringValue(body["user_nickname"]),
	})
	realtime.BroadcastMessage(eventID, userMessage)

	// 流式输出：正文增量（不含推理过程）经 socket 实时广播给事件房间，
	// 前端对话弹窗边生成边渲染，不再干等最终报告；返回值仍是完整回答。
	reply, err := s.core.LLM.ChatStream(ctx, trafficservice.EngineerChatSystemPrompt, prompt, func(delta string) {
		realtime.Broadcast(eventID, "chat_delta", map[string]any{"event_id": eventID, "delta": delta})
	})
	if err != nil {
		return nil, err
	}

	assistantMessage, _ := s.core.Store.AddMessage(domain.Message{
		EventID:         eventID,
		MessageFrom:     domain.RoleAssistant,
		MessageType:     "assistant_response",
		MessageContent:  trafficservice.EvidenceReplyContent(reply, event.Context),
		RoundID:         1,
		MessageCategory: "engineer_chat",
		SenderType:      "ai",
		ChatSessionID:   stringValue(body["chat_session_id"]),
	})
	realtime.BroadcastMessage(eventID, assistantMessage)
	if err := s.core.MarkReportSnapshot(ctx, eventID, event.Context); err != nil {
		return nil, err
	}

	return map[string]any{
		"reply":        reply,
		"message":      assistantMessage,
		"user_message": userMessage,
	}, nil
}

func (s *ChatService) History(ctx context.Context, eventID string) []domain.Message {
	return s.core.Store.ListMessages(eventID)
}

func (s *ChatService) NewSession(ctx context.Context) map[string]string {
	return map[string]string{"session_id": randomAccessToken()}
}

func (s *ChatService) Status(ctx context.Context, eventID string) map[string]string {
	return map[string]string{"event_id": eventID, "status": "idle"}
}

func (s *ChatService) engineerEventPrompt(event domain.Event, question string) string {
	var b strings.Builder
	for _, part := range s.engineerPromptParts(event, question) {
		b.WriteString(part.text)
	}
	return b.String()
}

type engineerPromptPart struct{ name, text string }

func (s *ChatService) engineerPromptParts(event domain.Event, question string) []engineerPromptPart {
	question = cleanEngineerQuestion(question)
	var b strings.Builder
	parts := []engineerPromptPart{}
	flush := func(name string) {
		parts = append(parts, engineerPromptPart{name, b.String()})
		b.Reset()
	}
	b.WriteString("# 安全事件完整信息\n\n")
	b.WriteString(fmt.Sprintf("事件ID: %s\n", event.EventID))
	b.WriteString(fmt.Sprintf("事件名称: %s\n", firstNonEmpty(event.EventName, event.Title, "未命名事件")))
	b.WriteString(fmt.Sprintf("事件描述: %s\n", firstNonEmpty(event.Message, "无描述")))
	b.WriteString(fmt.Sprintf("严重程度: %s\n", firstNonEmpty(event.Severity, "未知")))
	b.WriteString(fmt.Sprintf("事件来源: %s\n", firstNonEmpty(event.Source, "未知")))
	b.WriteString(fmt.Sprintf("事件状态: %s\n", firstNonEmpty(event.EventStatus, "未知")))
	b.WriteString(fmt.Sprintf("当前轮次: %d\n", event.CurrentRound))
	b.WriteString(fmt.Sprintf("创建时间: %s\n\n", event.CreatedAt.Format("2006-01-02 15:04:05")))
	flush("事件基本信息")
	evidenceContext := event.Context
	var evidenceErr error
	var prepared map[string]any
	_ = json.Unmarshal([]byte(event.Context), &prepared)
	if prepared["input_manifest"] == nil {
		evidenceContext, evidenceErr = s.core.EvidenceContext(context.Background(), event)
	}
	if evidenceErr != nil {
		evidenceContext = "证据快照暂不可用：" + evidenceErr.Error()
	}
	b.WriteString(fmt.Sprintf("事件上下文与证据摘要: %s\n\n", buildEngineerEvidenceContext(event.EventID, evidenceContext)))
	flush("事件上下文与明细样本")

	if len(event.Observables) > 0 {
		b.WriteString("## 可观察对象\n")
		for _, ioc := range event.Observables {
			b.WriteString(fmt.Sprintf("- type=%s value=%s role=%s\n", ioc.Type, ioc.Value, ioc.Role))
		}
		b.WriteString("\n")
	}
	flush("可观察对象")

	writeJSONSection(&b, "## 系统记录的任务", s.core.Store.ListTasks(event.EventID))
	flush("任务")
	writeJSONSection(&b, "## 系统记录的动作", s.core.Store.ListActions(event.EventID))
	flush("动作")
	writeJSONSection(&b, "## 系统记录的命令", s.core.Store.ListCommands(event.EventID))
	flush("命令")
	writeJSONSection(&b, "## 执行结果", s.core.Store.ListExecutions(event.EventID))
	flush("执行结果")
	writeJSONSection(&b, "## 事件总结", s.core.Store.ListSummaries(event.EventID))
	flush("事件总结")
	writeEngineerHistory(&b, s.core.Store.ListMessages(event.EventID))
	flush("最近工程师对话")

	b.WriteString("# 当前工程师问题\n")
	b.WriteString(question)
	b.WriteString("\n\n")
	flush("当前问题")
	b.WriteString(deepSOCEngineerAnswerGuide)
	flush("报告格式与回答要求")
	return parts
}

const deepSOCEngineerAnswerGuide = `# 回答要求
你是 DeepSOC 安全运营中心的 AI 助手，专门协助安全工程师处理安全事件。必须基于上面的完整事件上下文回答，不要要求用户再次提供事件详情。

回答时请像原版 DeepSOC 工程师助手一样体现分析深度。模型可以对全量 evidence_index 做跨明细、跨会话、时间序列和协议语义推理；确定性统计由系统预先计算，不能把统计量当成攻击成功证据：
1. 先判断事件本质：这是探测、漏洞利用尝试、有效入侵、误报，还是需要更多证据确认。
2. 结合事件基本信息、可观察对象、系统实际记录的任务/动作/执行结果、事件总结和历史对话。
3. 给出证据链：攻击源、受害目标、端口协议、命中规则、payload/IOC、时间线、已有处置。
4. 分析影响面：资产重要性、业务暴露面、是否可能成功、是否需要扩大排查。
5. 输出可执行处置建议：查询哪些日志、验证哪些现象、是否封禁、是否通知、如何持续观察。
6. 输出危险攻击概率（0-100%）及概率依据；关键证据必须按 1、2、3… 编号，引用 evidence_id，并指出该明细的具体问题。区分行为证据、成功性证据、排除性证据和背景统计。无法确认就明确写“无法确认”，不得编造。
7. 明确列出信息缺口，但即使信息不足，也要基于已有信息完成初步研判。

如果用户要求“分析该事件”或“形成报告”，请按以下结构直接生成报告：
## 事件概览
## 关键证据
## 攻击源与受影响资产分析
## 攻击链与风险判断
## 系统已记录的执行进展
## 后续处置建议
## 信息缺口
## 最终结论`

func cleanEngineerQuestion(question string) string {
	question = strings.TrimSpace(question)
	question = strings.TrimPrefix(question, "@AI")
	question = strings.TrimPrefix(question, "@ai")
	return strings.TrimSpace(question)
}

// jsonSectionMaxRunes 限制单个 JSON 区块(自动驾驶任务/动作/命令/执行/总结)的体量,
// 防止大事件把工程师对话 prompt 撑爆 16K 窗口;末尾的工程师问题因此不会被挤掉。
const jsonSectionMaxRunes = 1500

func writeJSONSection(b *strings.Builder, title string, v any) {
	b.WriteString(title)
	b.WriteString("\n")
	raw, _ := json.MarshalIndent(v, "", "  ")
	if string(raw) == "null" || string(raw) == "[]" {
		b.WriteString("暂无\n\n")
		return
	}
	if runes := []rune(string(raw)); len(runes) > jsonSectionMaxRunes {
		b.WriteString(string(runes[:jsonSectionMaxRunes]))
		b.WriteString("…(已截断)")
	} else {
		b.Write(raw)
	}
	b.WriteString("\n\n")
}

func writeEngineerHistory(b *strings.Builder, messages []domain.Message) {
	lines := []string{}
	for _, msg := range messages {
		if msg.MessageCategory != "engineer_chat" {
			continue
		}
		role := ""
		switch msg.SenderType {
		case "user":
			role = "工程师"
		case "ai":
			role = "AI助手"
		default:
			continue
		}
		content := strings.TrimSpace(msg.MessageContent)
		if content == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: %s", role, limitEngineerText(content, 1000)))
	}
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	// Retain recent turns within a fixed budget; long reports must not grow
	// every subsequent request without bound.
	remaining := 3000
	start := len(lines)
	for start > 0 {
		size := len([]rune(lines[start-1]))
		if size > remaining {
			break
		}
		remaining -= size
		start--
	}
	lines = lines[start:]
	b.WriteString("## 最近工程师对话\n")
	if len(lines) == 0 {
		b.WriteString("暂无历史对话\n\n")
		return
	}
	for _, line := range lines {
		b.WriteString("- ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
