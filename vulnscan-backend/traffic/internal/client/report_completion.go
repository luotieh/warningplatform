package client

import "context"

// Dedicated report telemetry; Chat and other callers keep their existing API.
type ReportCompletion struct {
	Reply            string
	PromptTokens     int
	CompletionTokens int
	FinishReason     string
}

func (c LLMClient) CompleteReport(ctx context.Context, system, prompt string) (ReportCompletion, error) {
	r, err := c.complete(ctx, system, prompt, c.effectiveMaxTokens(), nil)
	return ReportCompletion{r.Reply, r.PromptTokens, r.CompletionTokens, r.FinishReason}, err
}
