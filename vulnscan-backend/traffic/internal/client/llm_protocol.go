package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxLLMResponseBytes = 4 << 20

type completionResult struct {
	Endpoint         string
	Status           int
	Reply            string
	FinishReason     string
	PromptTokens     int
	CompletionTokens int
}

func llmAPIBase(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	for _, suffix := range []string{"/chat/completions", "/responses"} {
		base = strings.TrimSuffix(base, suffix)
	}
	return base
}

// Retry only a rejected protocol, never a timeout, quota failure or ambiguous 5xx.
// The same context bounds both attempts and preserves cancellation from the caller.
func (c LLMClient) complete(ctx context.Context, system, prompt string, budget int, onDelta func(string)) (completionResult, error) {
	startedAt := time.Now()
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if httpClient.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, httpClient.Timeout)
		defer cancel()
	}
	responses := strings.HasSuffix(strings.TrimRight(strings.TrimSpace(c.BaseURL), "/"), "/responses")
	for attempt := 0; attempt < 2; attempt++ {
		endpoint := chatCompletionsEndpoint(c.BaseURL)
		messages := []map[string]string{}
		if system != "" {
			messages = append(messages, map[string]string{"role": "system", "content": system})
		}
		messages = append(messages, map[string]string{"role": "user", "content": prompt})
		payload := map[string]any{"model": c.Model, "messages": messages, "stream": false, "max_tokens": budget}
		if responses {
			endpoint = llmAPIBase(c.BaseURL) + "/responses"
			payload = map[string]any{
				"model": c.Model, "instructions": system,
				"input":  []any{map[string]any{"role": "user", "content": []any{map[string]string{"type": "input_text", "text": prompt}}}},
				"stream": true, "store": false, "max_output_tokens": budget,
			}
		}
		// 需要实时输出时改用 SSE 流：正文增量经 onDelta 回调，
		// include_usage 让末帧带回真实 token 用量供遥测记录。
		if !responses && onDelta != nil {
			payload["stream"] = true
			payload["stream_options"] = map[string]any{"include_usage": true}
		}
		// Qwen 系模型可关闭思考链，避免推理过程耗尽 max_tokens 导致报告截断
		if !responses && c.DisableThinking {
			payload["chat_template_kwargs"] = map[string]any{"enable_thinking": false}
		}
		result := completionResult{Endpoint: endpoint}
		fail := func(detail string) (completionResult, error) {
			err := c.callError(endpoint, result.Status, detail)
			if e, ok := err.(*LLMCallError); ok {
				e.MaxTokens = budget
				if responses {
					e.TokenParameter = "max_output_tokens"
				}
			}
			return result, err
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return fail(err.Error())
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fail(err.Error())
		}
		req.Header.Set("Content-Type", "application/json")
		if responses || onDelta != nil {
			req.Header.Set("Accept", "text/event-stream, application/json")
		}
		if key := strings.TrimSpace(c.APIKey); key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return fail(err.Error())
		}
		result.Status = resp.StatusCode
		if resp.StatusCode >= 400 {
			b, readErr := readLLMBody(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return fail(readErr.Error())
			}
			detail := upstreamErrorDetail(b)
			if !responses && attempt == 0 && unsupportedChatEndpoint(resp.StatusCode, detail) && ctx.Err() == nil {
				responses = true
				continue
			}
			return fail(detail)
		}
		if responses {
			result.Reply, err = readResponsesReply(resp, onDelta)
		} else if onDelta != nil && strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			var usage chatUsage
			result.Reply, result.FinishReason, usage, err = readChatStream(resp, onDelta)
			result.PromptTokens = usage.PromptTokens
			result.CompletionTokens = usage.CompletionTokens
		} else {
			var b []byte
			b, err = readLLMBody(resp.Body)
			if err == nil {
				var usage chatUsage
				result.Reply, result.FinishReason, usage, err = readChatReply(b)
				result.PromptTokens = usage.PromptTokens
				result.CompletionTokens = usage.CompletionTokens
			}
		}
		resp.Body.Close()
		if err != nil {
			return fail(err.Error())
		}
		// 调用遥测：记录真实 token 用量、耗时与结束原因，用于排查估算偏差、
		// 输出截断(finish_reason=length)与超时，无需独立监控程序。
		slog.Info("LLM调用完成",
			"model", c.Model,
			"endpoint", sanitizeEndpoint(endpoint),
			"latency_ms", time.Since(startedAt).Milliseconds(),
			"prompt_tokens", result.PromptTokens,
			"completion_tokens", result.CompletionTokens,
			"finish_reason", result.FinishReason,
			"max_tokens", budget,
		)
		return result, nil
	}
	return completionResult{}, fmt.Errorf("LLM协议协商失败")
}

// sanitizeEndpoint 去掉 URL 中的凭据与参数，避免日志泄露。
func sanitizeEndpoint(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		return u.String()
	}
	return endpoint
}

func unsupportedChatEndpoint(status int, detail string) bool {
	if status != 400 && status != 404 && status != 405 && status != 422 && status != 500 && status != 501 {
		return false
	}
	d := strings.ToLower(detail)
	return strings.Contains(d, "/chat/completions") && (strings.Contains(d, "not supported") || strings.Contains(d, "unsupported") || strings.Contains(d, "does not support"))
}

func readLLMBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxLLMResponseBytes+1))
	if len(b) > maxLLMResponseBytes {
		return nil, fmt.Errorf("LLM响应超过大小限制")
	}
	return b, err
}

type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func readChatReply(b []byte) (string, string, chatUsage, error) {
	var out struct {
		Choices []struct {
			Finish  string `json:"finish_reason"`
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage chatUsage       `json:"usage"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", "", chatUsage{}, fmt.Errorf("上游响应不是有效的对话 JSON: %w", err)
	}
	if hasResponseError(out.Error) {
		return "", "", out.Usage, fmt.Errorf("%s", upstreamErrorDetail(b))
	}
	if len(out.Choices) == 0 {
		return "", "", out.Usage, fmt.Errorf("choices为空；%s", upstreamErrorDetail(b))
	}
	choice := out.Choices[0]
	reply := strings.TrimSpace(choice.Message.Content)
	if choice.Finish == "length" {
		return reply, choice.Finish, out.Usage, fmt.Errorf("模型输出达到 token 上限（completion_tokens=%d），未完成回答；若模型开启了思考模式(thinking)，推理链会占用输出预算，建议配置 llm_disable_thinking=true 或调大 llm_max_tokens", out.Usage.CompletionTokens)
	}
	if choice.Finish != "" && choice.Finish != "stop" {
		return reply, choice.Finish, out.Usage, fmt.Errorf("模型未正常完成回答: finish_reason=%s", choice.Finish)
	}
	if reply == "" {
		return "", choice.Finish, out.Usage, fmt.Errorf("模型未返回最终回答（content 为空）；推理内容不能作为最终报告")
	}
	return reply, choice.Finish, out.Usage, nil
}

// readChatStream 解析 chat/completions 的 SSE 流：只累计并回调正文增量
// （delta.content），推理内容（delta.reasoning_content 等）不转发、不保存，
// 前端因此能实时看到回答而不暴露思考过程。
func readChatStream(resp *http.Response, onDelta func(string)) (string, string, chatUsage, error) {
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, maxLLMResponseBytes+1))
	scanner.Buffer(make([]byte, 4096), maxLLMResponseBytes)
	var sb strings.Builder
	var usage chatUsage
	finish := ""
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
		if line != "" || len(data) == 0 {
			continue
		}
		payload := strings.Join(data, "\n")
		data = nil
		if payload == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				Finish string `json:"finish_reason"`
			} `json:"choices"`
			Usage *chatUsage      `json:"usage"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			return "", finish, usage, fmt.Errorf("对话流事件解析失败: %w", err)
		}
		if hasResponseError(chunk.Error) {
			return "", finish, usage, fmt.Errorf("%s", upstreamErrorDetail([]byte(payload)))
		}
		if chunk.Usage != nil {
			usage = *chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]
		if choice.Delta.Content != "" {
			sb.WriteString(choice.Delta.Content)
			if onDelta != nil {
				onDelta(choice.Delta.Content)
			}
		}
		if choice.Finish != "" {
			finish = choice.Finish
		}
	}
	if err := scanner.Err(); err != nil {
		return "", finish, usage, fmt.Errorf("对话流读取失败: %w", err)
	}
	reply := strings.TrimSpace(sb.String())
	if finish == "length" {
		return reply, finish, usage, fmt.Errorf("模型输出达到 token 上限（completion_tokens=%d），未完成回答；若模型开启了思考模式(thinking)，推理链会占用输出预算，建议配置 llm_disable_thinking=true 或调大 llm_max_tokens", usage.CompletionTokens)
	}
	if finish != "" && finish != "stop" {
		return reply, finish, usage, fmt.Errorf("模型未正常完成回答: finish_reason=%s", finish)
	}
	if reply == "" {
		return "", finish, usage, fmt.Errorf("模型未返回最终回答（content 为空）；推理内容不能作为最终报告")
	}
	return reply, finish, usage, nil
}

type responsesOutput struct {
	Status            string          `json:"status"`
	Error             json.RawMessage `json:"error"`
	IncompleteDetails struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Output []struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type    string `json:"type"`
			Text    string `json:"text"`
			Refusal string `json:"refusal"`
		} `json:"content"`
	} `json:"output"`
}

func hasResponseError(e json.RawMessage) bool {
	return len(e) > 0 && string(e) != "null"
}

func (r responsesOutput) finalText() (string, error) {
	if hasResponseError(r.Error) {
		return "", fmt.Errorf("Responses调用失败: %s", upstreamErrorDetail(append(append([]byte(`{"error":`), r.Error...), '}')))
	}
	if r.Status != "completed" {
		return "", fmt.Errorf("Responses未完成: status=%s reason=%s；若为 max_output_tokens 则输出已达到 token 上限", r.Status, r.IncompleteDetails.Reason)
	}
	var text []string
	for _, item := range r.Output {
		if item.Type != "message" || item.Role != "assistant" {
			continue
		}
		for _, part := range item.Content {
			if part.Type == "refusal" {
				return "", fmt.Errorf("模型拒绝回答: %s", part.Refusal)
			}
			if part.Type == "output_text" && part.Text != "" {
				text = append(text, part.Text)
			}
		}
	}
	reply := strings.TrimSpace(strings.Join(text, "\n"))
	if reply == "" {
		return "", fmt.Errorf("Responses未返回最终回答（output_text 为空）")
	}
	return reply, nil
}

// Streaming-only gateways are supported, but partial deltas are never a report.
// A completed response is required; cancellation and premature EOF remain errors.
func readResponsesReply(resp *http.Response, onDelta func(string)) (string, error) {
	r := bufio.NewReader(io.LimitReader(resp.Body, maxLLMResponseBytes+1))
	prefix, _ := r.Peek(5)
	stream := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") || string(prefix) == "data:" || string(prefix) == "event"
	if !stream {
		b, err := readLLMBody(r)
		if err != nil {
			return "", err
		}
		var out responsesOutput
		if err := json.Unmarshal(b, &out); err != nil {
			return "", fmt.Errorf("Responses响应解析失败: %w", err)
		}
		return out.finalText()
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), maxLLMResponseBytes)
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
		if line != "" || len(data) == 0 {
			continue
		}
		b := []byte(strings.Join(data, "\n"))
		data = nil
		if string(b) == "[DONE]" {
			break
		}
		var event struct {
			Type     string          `json:"type"`
			Delta    string          `json:"delta"`
			Response responsesOutput `json:"response"`
		}
		if err := json.Unmarshal(b, &event); err != nil {
			return "", fmt.Errorf("Responses流事件解析失败: %w", err)
		}
		switch event.Type {
		case "response.output_text.delta":
			// 只转发正文增量；推理摘要（reasoning_summary）等事件不转发。
			if event.Delta != "" && onDelta != nil {
				onDelta(event.Delta)
			}
		case "response.completed", "response.failed", "response.incomplete":
			return event.Response.finalText()
		case "error":
			return "", fmt.Errorf("Responses流错误: %s", upstreamErrorDetail(b))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("Responses流读取失败: %w", err)
	}
	return "", fmt.Errorf("Responses流提前结束，未收到 response.completed；不保存不完整报告")
}
