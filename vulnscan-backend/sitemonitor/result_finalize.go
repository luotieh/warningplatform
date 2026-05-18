package sitemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// MonitorIssueNotifier 在监测发现有效问题时回调（可选，由 Service 注册）。
type MonitorIssueNotifier func(ctx context.Context, exec *model.MonitorExecution)

var monitorIssueNotifier MonitorIssueNotifier

func SetMonitorIssueNotifier(fn MonitorIssueNotifier) {
	monitorIssueNotifier = fn
}

// FinalizeMonitorResult 将 Agent/嵌入式执行结果写入 monitor_executions，并解析 has_issue、处置状态与明细表。
func FinalizeMonitorResult(ctx context.Context, db *gorm.DB, ar *model.MonitorAgentResult) error {
	if db == nil || ar == nil || ar.ExecutionID == "" {
		return fmt.Errorf("invalid finalize params")
	}

	var exec model.MonitorExecution
	if err := db.WithContext(ctx).Where("id = ?", ar.ExecutionID).First(&exec).Error; err != nil {
		return fmt.Errorf("execution not found: %w", err)
	}

	if ar.Dimension == "" {
		ar.Dimension = exec.Dimension
	}
	if ar.TaskID == "" {
		ar.TaskID = exec.TaskID
	}
	if ar.URL == "" {
		ar.URL = exec.URL
	}

	if exec.Status == "success" || exec.Status == "failed" {
		canOverride := exec.Status == "failed" && exec.ReapedAt != nil && ar.Status == "success"
		if !canOverride {
			slog.Debug("[Monitor] execution already terminal, skip finalize", "eid", ar.ExecutionID, "status", exec.Status)
			return nil
		}
	}

	startedAt := parseTime(ar.StartedAt)
	finishedAt := parseTime(ar.FinishedAt)

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		exec.AgentID = ar.AgentID
		exec.Status = ar.Status
		exec.Error = ar.Error
		exec.StartedAt = startedAt
		exec.FinishedAt = finishedAt
		exec.ResultJSON = ar.Result
		exec.ReapedAt = nil

		if ar.Status == "failed" {
			exec.HasIssue = false
			exec.Disposition = model.MonitorDispositionValid
			return tx.Save(&exec).Error
		}

		applyResultSemantics(tx, &exec, ar)

		if exec.HasIssue {
			exec.Disposition = model.MonitorDispositionPending
		} else {
			exec.Disposition = model.MonitorDispositionValid
		}

		if err := tx.Save(&exec).Error; err != nil {
			return err
		}

		if exec.HasIssue && monitorIssueNotifier != nil {
			execCopy := exec
			go monitorIssueNotifier(context.Background(), &execCopy)
		}
		return nil
	})
}

func applyResultSemantics(tx *gorm.DB, exec *model.MonitorExecution, ar *model.MonitorAgentResult) {
	switch ar.Dimension {
	case "sensitive_word":
		var r model.MonitorSensitiveWordResult
		if err := json.Unmarshal([]byte(ar.Result), &r); err != nil {
			exec.Error = fmt.Sprintf("结果解析失败: %v", err)
			exec.HasIssue = true
		} else {
			exec.HasIssue = r.HasHit
			if r.Error != "" {
				exec.Error = r.Error
			}
			if tx != nil {
				_ = SaveSensitiveWordResult(tx, ar.ExecutionID, ar.TaskID, &r)
			}
		}
	case "sensitive_file":
		var r model.MonitorSensitiveFileResult
		if err := json.Unmarshal([]byte(ar.Result), &r); err != nil {
			exec.Error = fmt.Sprintf("结果解析失败: %v", err)
			exec.HasIssue = true
		} else {
			exec.HasIssue = r.HasHit
			if r.Error != "" {
				exec.Error = r.Error
			}
			if tx != nil {
				_ = SaveSensitiveFileResult(tx, ar.ExecutionID, ar.TaskID, &r)
			}
		}
	case "tamper":
		var tr model.MonitorTamperResult
		if err := json.Unmarshal([]byte(ar.Result), &tr); err != nil {
			exec.HasIssue = jsonBool(ar.Result, "tampered")
		} else {
			exec.HasIssue = tr.Tampered
			if tr.BaselineUpdate != nil {
				if tx != nil {
					_ = SaveBaselineFromUpdate(context.Background(), tx, ar.ExecutionID, ar.URL, ar.AgentID, tr.BaselineUpdate)
				}
			}
		}
	case "blacklink":
		exec.HasIssue = jsonBool(ar.Result, "has_black")
	case "availability":
		exec.HasIssue = !jsonBool(ar.Result, "available")
	case "domain_hijack":
		exec.HasIssue = jsonBool(ar.Result, "hijacked")
	default:
		// 未知维度：若结果体含 has_hit/has_issue 则尽量识别
		if jsonBool(ar.Result, "has_hit") || jsonBool(ar.Result, "has_issue") ||
			jsonBool(ar.Result, "tampered") || jsonBool(ar.Result, "has_black") ||
			jsonBool(ar.Result, "hijacked") {
			exec.HasIssue = true
		} else if jsonBool(ar.Result, "available") {
			exec.HasIssue = false
		}
	}
}

// FinalizeFromTaskResult 供 node-api / 嵌入式 Agent 上报的通用 TaskResult 结构使用。
func FinalizeFromTaskResult(ctx context.Context, db *gorm.DB, executionID, agentID, status, errMsg, result, startedAt, finishedAt string) error {
	var exec model.MonitorExecution
	if err := db.WithContext(ctx).Where("id = ?", executionID).First(&exec).Error; err != nil {
		return err
	}
	ar := &model.MonitorAgentResult{
		AgentID:     agentID,
		ExecutionID: executionID,
		TaskID:      exec.TaskID,
		Dimension:   exec.Dimension,
		URL:         exec.URL,
		Status:      status,
		Result:      result,
		Error:       errMsg,
		StartedAt:   startedAt,
		FinishedAt:  finishedAt,
	}
	return FinalizeMonitorResult(ctx, db, ar)
}
