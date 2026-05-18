package monitoragent

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"vulnscan-backend/agent"

	"gorm.io/gorm"
)

type DBExecutor struct {
	db          *gorm.DB
	pageService *PageService
	analysis    *AnalysisEngine
}

func NewDBExecutor(db *gorm.DB) *DBExecutor {
	return &DBExecutor{db: db}
}

func (e *DBExecutor) Type() string { return "monitor" }

func (e *DBExecutor) Init(ctx context.Context) error {
	e.pageService = NewPageService()
	e.analysis = NewAnalysisEngineFromDB(e.db)
	e.analysis.RefreshRules(ctx)
	return nil
}

func (e *DBExecutor) Execute(ctx context.Context, payload json.RawMessage) *agent.TaskResult {
	var msg TaskMessage
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

	slog.Info("embedded monitor exec", "execution_id", msg.ExecutionID, "dimension", msg.Dimension, "url", msg.URL)

	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	if msg.Dimension == "sensitive_file" {
		result.Status = "success"
		analyzed, aErr := e.analysis.Analyze(ctx, msg.Dimension, "", msg.URL, &msg)
		if aErr != nil {
			result.Status = "failed"
			result.Error = aErr.Error()
		} else {
			result.Result = analyzed
		}
		return result
	}

	snap, err := e.pageService.FetchPage(ctx, msg.URL)
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

func (e *DBExecutor) Close() error {
	if e.pageService != nil {
		e.pageService.Close()
	}
	return nil
}

func (e *DBExecutor) RefreshRules(ctx context.Context) {
	if e.analysis != nil {
		e.analysis.RefreshRules(ctx)
	}
}
