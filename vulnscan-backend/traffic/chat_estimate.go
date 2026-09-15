package traffic

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"vulnscan-backend/traffic/internal/client"
	trafficservice "vulnscan-backend/traffic/internal/service"
)

// Estimate describes the exact prompt construction without calling the model or
// writing messages. A concurrent message can change the subsequent send's history.
func (s *ChatService) Estimate(eventID, question string) (map[string]any, error) {
	if strings.TrimSpace(question) == "" {
		return nil, errors.New("message不能为空")
	}
	event, ok := s.core.Store.GetEvent(eventID)
	if !ok {
		return nil, errors.New("事件不存在")
	}
	parts := append([]engineerPromptPart{{"系统提示词", trafficservice.EngineerChatSystemPrompt}}, s.engineerPromptParts(event, question)...)
	sections := make([]map[string]any, 0, len(parts))
	var whole strings.Builder
	for _, part := range parts {
		sections = append(sections, map[string]any{"name": part.name, "characters": len([]rune(part.text)), "estimated_tokens": trafficservice.EstimatePromptTokens(part.text)})
		whole.WriteString(part.text)
	}
	model, profile, timeout := "", "", 15
	if llm := s.core.LLM; llm != nil {
		model = llm.Model
		profile = fmt.Sprintf("%x", sha256.Sum256([]byte(llm.BaseURL+"|"+llm.Model)))
		if llm.HTTP != nil && llm.HTTP.Timeout > 0 {
			timeout = int(llm.HTTP.Timeout.Seconds())
		}
	}
	return map[string]any{
		"model": model, "profile": profile, "timeout_seconds": timeout,
		"estimated_input_tokens":    trafficservice.EstimatePromptTokens(whole.String()) + 12,
		"message_overhead_estimate": 12, "output_max_tokens": client.ChatMaxTokens,
		"sections": sections, "is_estimate": true,
		"estimate_method": "CJK字符×0.7，其余字符÷3.5，合计×1.1并向上取整；另估计12个消息封装token。实际以模型usage为准。",
	}, nil
}
