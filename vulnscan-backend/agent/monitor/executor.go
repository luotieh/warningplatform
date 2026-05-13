package monitor

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/monitoragent"
)

type Executor struct {
	masterURL   string
	token       string
	pageService *monitoragent.PageService
	analysis    *monitoragent.AnalysisEngine
}

func NewExecutor(masterURL, token string) *Executor {
	return &Executor{
		masterURL: masterURL,
		token:     token,
	}
}

func (e *Executor) Type() string { return "monitor" }

func (e *Executor) Init(ctx context.Context) error {
	e.pageService = monitoragent.NewPageService()
	fetcher := &clientRuleFetcher{client: agent.NewClient(e.masterURL, e.token)}
	e.analysis = monitoragent.NewAnalysisEngine(fetcher)
	e.analysis.RefreshRules(ctx)
	return nil
}

func (e *Executor) Execute(ctx context.Context, payload json.RawMessage) *agent.TaskResult {
	var msg monitoragent.TaskMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return &agent.TaskResult{
			Status:     "failed",
			Error:      "invalid monitor payload: " + err.Error(),
			StartedAt:  time.Now().UTC().Format(time.RFC3339),
			FinishedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	result := &agent.TaskResult{
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}

	slog.Info("monitor exec", "execution_id", msg.ExecutionID, "dimension", msg.Dimension, "url", msg.URL)

	snap, err := e.pageService.FetchPage(ctx, msg.URL)
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result
	}

	result.Status = "success"
	if snap != nil {
		raw, _ := json.Marshal(snap)
		snapshotJSON := string(raw)

		analyzed, aErr := e.analysis.Analyze(ctx, msg.Dimension, snapshotJSON, msg.URL, &msg)
		if aErr != nil {
			slog.Warn("analysis failed, using raw snapshot", "dimension", msg.Dimension, "error", aErr)
			result.Result = snapshotJSON
		} else {
			result.Result = analyzed
		}
	}

	return result
}

func (e *Executor) Close() error {
	if e.pageService != nil {
		e.pageService.Close()
	}
	return nil
}

func (e *Executor) RefreshRules(ctx context.Context) {
	if e.analysis != nil {
		e.analysis.RefreshRules(ctx)
	}
}

type clientRuleFetcher struct {
	client *agent.Client
}

func (f *clientRuleFetcher) FetchRules(ctx context.Context) (map[string]json.RawMessage, error) {
	return f.client.GetRules(ctx)
}
