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
	return m.Model.Complete(ctx, call)
}
