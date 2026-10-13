package client

import "context"

// Dedicated report telemetry; Chat and other callers keep their existing API.
type ReportCompletion struct {
	Usage            map[string]any
	Reply            string
	PromptTokens     int
	CompletionTokens int
	FinishReason     string
}

func (c LLMClient) CompleteReport(ctx context.Context, system, prompt string) (ReportCompletion, error) {
	r, err := c.complete(ctx, system, prompt, c.effectiveMaxTokens(), nil)
	return ReportCompletion{Reply: r.Reply, PromptTokens: r.PromptTokens, CompletionTokens: r.CompletionTokens, FinishReason: r.FinishReason, Usage: r.Usage}, err
}
