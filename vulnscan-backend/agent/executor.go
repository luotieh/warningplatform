package agent

import (
	"context"
	"encoding/json"
)

type Executor interface {
	Type() string
	Init(ctx context.Context) error
	Execute(ctx context.Context, payload json.RawMessage) *TaskResult
	Close() error
}
