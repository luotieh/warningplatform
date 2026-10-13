package service

import (
	"context"
	"fmt"
	"vulnscan-backend/evidence"
)

type reportSemanticAuditModel struct {
	Model evidence.SemanticModel
	Save  func(context.Context, evidence.SemanticCall) error
}

func (m reportSemanticAuditModel) Complete(ctx context.Context, call evidence.SemanticCall) (string, error) {
	call.System += "\n报告专用：每个explanation不超过100字；每条quotes只逐字摘录15至30字的关键字段或完整短字段，材料和事实ID仍完整引用；alternatives与gaps各最多3条简短句，不罗列缺乏依据的剧情。"
	if err := m.Save(ctx, call); err != nil {
		return "", fmt.Errorf("semantic_input_audit_write_failed: %w", err)
	}
	r := reportLogFrom(ctx)
	n := 0
	if r != nil {
		r.mu.Lock()
		r.semantic++
		n = r.semantic
		r.mu.Unlock()
		r.write(fmt.Sprintf("semantic-call-%02d-request.json", n), map[string]any{"system": call.System, "user": call.Prompt, "max_output_tokens": call.MaxOutputTokens, "sent": false, "boundary": "semantic model adapter"})
	}
	reply, err := m.Model.Complete(ctx, call)
	if r != nil {
		r.write(fmt.Sprintf("semantic-call-%02d-response.json", n), map[string]any{"reply": reply, "error": err != nil, "usage_available": false, "request_invoked": true})
	}
	return reply, err
}
