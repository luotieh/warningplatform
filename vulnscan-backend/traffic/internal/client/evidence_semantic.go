package client

import (
	"context"
	"fmt"

	"vulnscan-backend/evidence"
)

// EvidenceSemanticModel adapts the configured transport without coupling the
// evidence engine to traffic services. Copying the client keeps report budgets
// unchanged; each semantic call supplies its own enforced output token limit.
type EvidenceSemanticModel struct{ Client LLMClient }

var _ evidence.SemanticModel = EvidenceSemanticModel{}

func (m EvidenceSemanticModel) Complete(ctx context.Context, call evidence.SemanticCall) (string, error) {
	if call.MaxOutputTokens <= 0 {
		return "", fmt.Errorf("positive semantic output token budget required")
	}
	if !m.Client.Enabled() {
		return "", fmt.Errorf("semantic model not configured")
	}
	c := m.Client
	c.MaxTokens = call.MaxOutputTokens
	return c.Chat(ctx, call.System, call.Prompt)
}
