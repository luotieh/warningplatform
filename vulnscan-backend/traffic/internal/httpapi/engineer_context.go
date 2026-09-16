package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"

	"vulnscan-backend/traffic/internal/domain"
)

func (s *Server) engineerEventPrompt(event domain.Event, question string) string {
	question = cleanEngineerQuestion(question)
	var b strings.Builder
	b.WriteString("# 安全事件完整信息\n\n")
	b.WriteString(fmt.Sprintf("事件ID: %s\n", event.EventID))
	b.WriteString(fmt.Sprintf("事件名称: %s\n", firstNonEmpty(event.EventName, event.Title, "未命名事件")))
	b.WriteString(fmt.Sprintf("事件描述: %s\n", firstNonEmpty(event.Message, "无描述")))
	b.WriteString(fmt.Sprintf("事件上下文: %s\n", firstNonEmpty(event.Context, "无上下文")))
	b.WriteString(fmt.Sprintf("严重程度: %s\n", firstNonEmpty(event.Severity, "未知")))
	b.WriteString(fmt.Sprintf("事件来源: %s\n", firstNonEmpty(event.Source, "未知")))
	b.WriteString(fmt.Sprintf("事件状态: %s\n", firstNonEmpty(event.EventStatus, "未知")))
	b.WriteString(fmt.Sprintf("当前轮次: %d\n", event.CurrentRound))
	b.WriteString(fmt.Sprintf("创建时间: %s\n\n", event.CreatedAt.Format("2006-01-02 15:04:05")))

	if len(event.Observables) > 0 {
		b.WriteString("## 可观察对象\n")
		for _, ioc := range event.Observables {
			b.WriteString(fmt.Sprintf("- type=%s value=%s role=%s\n", ioc.Type, ioc.Value, ioc.Role))
		}
		b.WriteString("\n")
	}

	writeJSONSection(&b, "## 系统记录的任务", s.services.Store.ListTasks(event.EventID))
	writeJSONSection(&b, "## 系统记录的动作", s.services.Store.ListActions(event.EventID))
	writeJSONSection(&b, "## 系统记录的命令", s.services.Store.ListCommands(event.EventID))
	writeJSONSection(&b, "## 执行结果", s.services.Store.ListExecutions(event.EventID))
	writeJSONSection(&b, "## 事件总结", s.services.Store.ListSummaries(event.EventID))
	writeEngineerHistory(&b, s.services.Store.ListMessages(event.EventID))

	b.WriteString("# 当前工程师问题\n")
	b.WriteString(question)
	b.WriteString("\n\n")
	b.WriteString(deepSOCEngineerAnswerGuide)
	return b.String()
}

const deepSOCEngineerAnswerGuide = `# 回答要求
你是 DeepSOC 安全运营中心的 AI 助手，专门协助安全工程师处理安全事件。必须基于上面的完整事件上下文回答，不要要求用户再次提供事件详情。

回答时请像原版 DeepSOC 工程师助手一样体现分析深度：
1. 先判断事件本质：这是探测、漏洞利用尝试、有效入侵、误报，还是需要更多证据确认。
2. 结合事件基本信息、可观察对象、系统实际记录的任务/动作/执行结果、事件总结和历史对话。
3. 给出证据链：攻击源、受害目标、端口协议、命中规则、payload/IOC、时间线、已有处置。
4. 分析影响面：资产重要性、业务暴露面、是否可能成功、是否需要扩大排查。
5. 输出可执行处置建议：查询哪些日志、验证哪些现象、是否封禁、是否通知、如何持续观察。
6. 明确列出信息缺口，但即使信息不足，也要基于已有信息完成初步研判。

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

// jsonSectionMaxRunes 限制单个 JSON 区块体量,防止大事件撑爆 16K 窗口(与 chat_service 一致)。
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
		lines = append(lines, fmt.Sprintf("%s: %s", role, content))
	}
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
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
