package monitoragent

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/sitemonitor/analyzer"

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

	snap, err := e.pageService.FetchPage(ctx, msg.URL, msg.RequestHost)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result
	}

	result.Status = "success"
	if snap != nil {
		if len(snap.Screenshot) > 0 {
			result.ScreenshotData = snap.Screenshot
		}

		raw, _ := json.Marshal(snap)
		snapshotJSON := string(raw)

		analyzed, output, aErr := e.analysis.AnalyzeWithOutput(ctx, msg.Dimension, snapshotJSON, msg.URL, &msg)
		if aErr != nil {
			slog.Warn("analysis failed, using raw snapshot", "dimension", msg.Dimension, "error", aErr)
			if msg.Dimension == "availability" {
				result.Result = BuildAvailabilityResultJSON(snapshotJSON, nil)
			} else {
				result.Result = snapshotJSON
			}
		} else {
			result.Result = analyzed
		}

		if output != nil && output.HasIssue {
			annotations := BuildAnnotationsFromOutput(msg.Dimension, output)
			if len(annotations) > 0 {
				annotatedData := e.pageService.CaptureAnnotatedScreenshot(ctx, msg.URL, annotations)
				if len(annotatedData) > 0 {
					result.AnnotatedScreenshotData = annotatedData
					slog.Info("[Monitor] 标注截图已生成", "dimension", msg.Dimension, "url", msg.URL, "annotations", len(annotations))
				}
			}

			if msg.Dimension == "blacklink" {
				result.ExtraScreenshots = e.captureBlacklinkTargets(ctx, output)
			}
		}
	}

	return result
}

func (e *DBExecutor) captureBlacklinkTargets(ctx context.Context, output *analyzer.Output) []agent.ExtraScreenshot {
	if output == nil || output.DetailsJSON == "" {
		return nil
	}
	var details struct {
		BlacklinkMatches []struct {
			URL string `json:"url"`
		} `json:"blacklink_matches"`
	}
	if json.Unmarshal([]byte(output.DetailsJSON), &details) != nil {
		return nil
	}

	const maxTargets = 5
	var screenshots []agent.ExtraScreenshot
	for i, m := range details.BlacklinkMatches {
		if i >= maxTargets || m.URL == "" {
			break
		}
		data := e.pageService.CaptureSimpleScreenshot(ctx, m.URL)
		if len(data) > 0 {
			screenshots = append(screenshots, agent.ExtraScreenshot{
				Label: "暗链目标",
				URL:   m.URL,
				Data:  data,
			})
			slog.Info("[Monitor] 暗链目标截图已生成", "target_url", m.URL)
		}
	}
	return screenshots
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
