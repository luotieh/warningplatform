package sitemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

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
		ar.TaskID = exec.PathTaskID
		if ar.TaskID == "" {
			ar.TaskID = exec.TargetID
		}
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

		if exec.HasIssue {
			issueKey := model.MakeIssueKey(exec.URL, exec.Dimension, exec.TargetID, exec.PathTaskID)
			exec.IssueKey = issueKey
			now := time.Now()
			merged, mergeErr := mergeIntoExistingIssue(tx, &exec, issueKey, now)
			if mergeErr != nil {
				slog.Warn("[Monitor] issue merge failed, keeping as new", "eid", exec.ID, "err", mergeErr)
			}
			if merged {
				exec.Disposition = "merged"
				return tx.Save(&exec).Error
			}
			exec.FirstSeenAt = &now
			exec.OccurrenceCount = 1
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

// mergeIntoExistingIssue 查找同一问题键下的已有未处置记录，
// 将本次执行结果合并到已有记录（更新结果、递增次数），返回 true 表示已合并。
func mergeIntoExistingIssue(tx *gorm.DB, exec *model.MonitorExecution, issueKey string, now time.Time) (bool, error) {
	var existing model.MonitorExecution
	err := tx.Where("issue_key = ? AND disposition = ? AND id != ? AND has_issue = ?",
		issueKey, model.MonitorDispositionPending, exec.ID, true).
		Order("created_at DESC").
		First(&existing).Error
	if err != nil {
		return false, nil
	}

	updates := map[string]any{
		"result_json":      exec.ResultJSON,
		"started_at":       exec.StartedAt,
		"finished_at":      exec.FinishedAt,
		"agent_id":         exec.AgentID,
		"error":            exec.Error,
		"created_at":       now,
		"occurrence_count": existing.OccurrenceCount + 1,
	}
	if err := tx.Model(&model.MonitorExecution{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
		return false, fmt.Errorf("update existing issue: %w", err)
	}

	slog.Info("[Monitor] merged duplicate issue into existing",
		"existing_id", existing.ID, "new_id", exec.ID,
		"issue_key", issueKey, "count", existing.OccurrenceCount+1)
	return true, nil
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
		autoAccepted := jsonBool(ar.Result, "auto_accepted")
		var tr model.MonitorTamperResult
		if err := json.Unmarshal([]byte(ar.Result), &tr); err != nil {
			exec.HasIssue = jsonBool(ar.Result, "tampered")
		} else {
			if autoAccepted {
				exec.HasIssue = false
				slog.Info("[Monitor] 篡改检测自动接受正常更新", "eid", ar.ExecutionID, "url", ar.URL)
			} else {
				exec.HasIssue = tr.Tampered
			}
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
		if tx != nil && exec.TargetID != "" {
			autoFillExpectedIPs(tx, exec.TargetID, ar.Result)
		}
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
		TaskID:      exec.PathTaskID,
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

func autoFillExpectedIPs(db *gorm.DB, targetID, resultJSON string) {
	var target model.MonitorTarget
	if err := db.Where("id = ?", targetID).Select("id, expected_ips").First(&target).Error; err != nil {
		return
	}
	if target.ExpectedIPs != "" {
		return
	}
	var parsed struct {
		ResolvedIPs []string `json:"resolved_ips"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &parsed); err != nil || len(parsed.ResolvedIPs) == 0 {
		return
	}
	ips := strings.Join(parsed.ResolvedIPs, ",")
	if err := db.Model(&model.MonitorTarget{}).Where("id = ? AND (expected_ips = '' OR expected_ips IS NULL)", targetID).
		Update("expected_ips", ips).Error; err != nil {
		slog.Warn("[Monitor] auto-fill expected_ips failed", "target_id", targetID, "err", err)
		return
	}
	slog.Info("[Monitor] auto-filled expected_ips from DNS", "target_id", targetID, "ips", ips)
}
