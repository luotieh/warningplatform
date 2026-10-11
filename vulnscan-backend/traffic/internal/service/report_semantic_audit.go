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
	if err := m.Save(ctx, call); err != nil {
		return "", fmt.Errorf("semantic_input_audit_write_failed: %w", err)
	}
	return m.Model.Complete(ctx, call)
}
