package service

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/realtime"
)

// agentWorkflowInflight 保证同一事件的分析同一时刻只跑一条，避免「查看报告」重推
// 与摄入路径并发触发两次 LLM 调用。
var agentWorkflowInflight sync.Map // eventID -> struct{}

// RunAgentWorkflowAsync 在后台跑事件分析，并与 HTTP 请求上下文解耦：
// 分析依赖 LLM、耗时较长，绝不能因请求返回/前端超时而被取消（否则报告页会看到
// "context canceled"）。限时由 LLM 客户端自身的 http.Client.Timeout 负责；进度/结果
// 通过 realtime 广播与消息流回传，前端用 websocket 增量渲染。
func (s Services) RunAgentWorkflowAsync(eventID string) {
	if strings.TrimSpace(eventID) == "" {
		return
	}
	if _, running := agentWorkflowInflight.LoadOrStore(eventID, struct{}{}); running {
		return
	}
	go func() {
		defer agentWorkflowInflight.Delete(eventID)
		_ = s.RunAgentWorkflow(context.Background(), eventID)
	}()
}

func (s Services) RunAgentWorkflow(ctx context.Context, eventID string) error {
	event, ok := s.Store.GetEvent(eventID)
	if !ok {
		return fmt.Errorf("event not found: %s", eventID)
	}
	roundID := event.CurrentRound
	if roundID == 0 {
		roundID = 1
	}
	if hasAgentWorkflowMessages(s.Store.ListMessages(eventID)) {
		return nil
	}

	_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "processing"})

	health := s.LLM.HealthCheck(ctx)
	if !health.Configured || !health.OK {
		err := fmt.Errorf("LLM不可用，请先在配置页面填写并验证可用的LLM参数: %s", firstNonEmpty(health.Error, "health check failed"))
		_ = s.addLLMConfigRequiredMessage(eventID, roundID, err.Error())
		// 事件状态回到 pending：列表里显示「未分析/待分析」而不是「需配置LLM」。
		// LLM 修好后会自动重试（RoleSystem 提示消息不计入 hasAgentWorkflowMessages）；
		// 「需配置LLM」的提示仍通过消息流与实时广播在报告详情里呈现。
		_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "pending"})
		realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "llm_config_required", "message": err.Error()})
		return err
	}

	reply, err := s.LLM.Chat(ctx, autoAnalysisPrompt(event))
	if err != nil {
		err = fmt.Errorf("LLM自动分析失败，请检查LLM配置: %w", err)
		_ = s.addLLMConfigRequiredMessage(eventID, roundID, err.Error())
		// 同上：保持 pending（列表显示未分析），等 LLM 恢复后自动重试。
		_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "pending"})
		realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "llm_config_required", "message": err.Error()})
		return err
	}

	sm, err := s.Store.AddSummary(domain.Summary{EventID: eventID, RoundID: roundID, EventSummary: reply})
	if err != nil {
		return err
	}
	_ = s.addAgentMessage(eventID, domain.RoleExpert, "event_summary", roundID,
		llmExpertResponse(event, roundID, sm, reply))
	_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "round_finished"})
	realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "round_finished"})
	return nil
}

func (s Services) addLLMConfigRequiredMessage(eventID string, roundID int, text string) error {
	return s.addAgentMessage(eventID, domain.RoleSystem, "llm_config_required", roundID, map[string]any{
		"type":          "llm_config_required",
		"event_id":      eventID,
		"round_id":      roundID,
		"response_text": text,
	})
}

func autoAnalysisPrompt(event domain.Event) string {
	return fmt.Sprintf(`你是 DeepSOC 自动分析引擎。请仅基于下面的安全事件信息生成自动分析结果，不要编造未提供的日志、资产或情报事实。

输出要求：
1. 使用中文 Markdown。
2. 保持原版 DeepSOC 自动驾驶分析风格，覆盖 Captain 研判、Manager 动作拆解、Operator 命令建议、Executor 应由外部剧本验证的证据项、Expert 总结。
3. 明确区分“已知事实”“待验证证据”“建议执行动作”，不要把未执行的剧本结果写成已完成。
4. 如果信息不足，必须写清缺口和下一步需要查询的数据。

事件ID：%s
事件名称：%s
严重级别：%s
来源：%s
描述：%s
上下文：%s
可观察对象：%s`,
		event.EventID,
		firstNonEmpty(event.EventName, event.Title, "未命名事件"),
		firstNonEmpty(event.Severity, "unknown"),
		firstNonEmpty(event.Source, "unknown"),
		firstNonEmpty(event.Message, "无"),
		firstNonEmpty(event.Context, "无"),
		formatObservables(event.Observables),
	)
}

func formatObservables(items []domain.IOC) string {
	if len(items) == 0 {
		return "无"
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, fmt.Sprintf("- type=%s role=%s value=%s", item.Type, item.Role, item.Value))
	}
	return strings.Join(lines, "\n")
}

func llmExpertResponse(event domain.Event, roundID int, sm domain.Summary, reply string) map[string]any {
	return map[string]any{
		"type":          "llm_response",
		"from":          domain.RoleExpert,
		"to":            []string{domain.RoleCaptain},
		"event_id":      event.EventID,
		"round_id":      roundID,
		"response_type": "SUMMARY",
		"response_text": reply,
		"suggestions":   []string{"当前结果由已配置 LLM 生成；如需执行封禁、取证或资产查询，请接入对应外部剧本/执行器。"},
	}
}

func hasAgentWorkflowMessages(messages []domain.Message) bool {
	for _, msg := range messages {
		switch NormalizeMessageFrom(msg.MessageFrom) {
		case domain.RoleCaptain, domain.RoleManager, domain.RoleOperator, domain.RoleExecutor, domain.RoleExpert:
			return true
		}
	}
	return false
}

func (s Services) addAgentMessage(eventID, from, messageType string, roundID int, data any) error {
	from = NormalizeMessageFrom(from)
	m, err := s.Store.AddMessage(domain.Message{
		EventID:         eventID,
		MessageFrom:     from,
		MessageType:     messageType,
		MessageContent:  StandardContent(data),
		RoundID:         roundID,
		MessageCategory: "agent",
		SenderType:      SenderType(from),
	})
	if err == nil {
		realtime.BroadcastMessage(eventID, m)
		_ = s.publish(context.Background(), "notifications.frontend."+eventID+"."+from+"."+messageType, eventID, from, m)
	}
	return err
}
