package analyzer

import (
	"context"

	"vulnscan-backend/model"
)

type Input struct {
	ExecutionID  string
	TaskID       string
	URL          string
	SnapshotJSON string
	Baseline     *model.MonitorBaseline
}

type Output struct {
	HasIssue       bool
	Severity       string
	BaselineUpdate *model.MonitorBaselineUpdate
	DetailsJSON    string
}

type Analyzer interface {
	Dimension() string
	Analyze(ctx context.Context, input *Input) (*Output, error)
}

type RuleAccessor interface {
	GetModuleRules(moduleKey string) ([]byte, error)
	GetAllRules() (map[string][]byte, error)
}

type Registry struct {
	analyzers map[string]Analyzer
}

func NewRegistry() *Registry {
	return &Registry{analyzers: make(map[string]Analyzer)}
}

func (r *Registry) Register(a Analyzer) {
	r.analyzers[a.Dimension()] = a
}

func (r *Registry) Get(dimension string) (Analyzer, bool) {
	a, ok := r.analyzers[dimension]
	return a, ok
}
