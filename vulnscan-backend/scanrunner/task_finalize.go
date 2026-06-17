package scanrunner

import (
	"context"
	"log/slog"

	"vulnscan-backend/knowledge/nuclei"
	"vulnscan-backend/model"
)

func (r *Runner) finalizeAfterRun(ctx context.Context) {
	nuclei.GetGlobalTemplateDedup().CleanupTask(r.task.ID)

	status := r.progress.Get().Status
	if status == "" {
		var row model.ScanTask
		if err := r.db.Select("status").First(&row, "id = ?", r.task.ID).Error; err == nil {
			status = row.Status
		}
	}
	r.task.Status = status

	switch r.task.Type {
	case model.TaskTypeAssetEnrich:
		if status == model.TaskStatusCompleted || status == model.TaskStatusPartial {
			if err := SyncAssetTableAfterEnrichScan(r.db, &r.task); err != nil {
				slog.Warn("[Runner] 资产富化回写失败", "task_id", r.task.ID, "error", err)
			}
		}
		CleanupAssetEnrichTask(r.db, &r.task)
	case model.TaskTypeAssetDiscovery:
		if status == model.TaskStatusCompleted || status == model.TaskStatusPartial ||
			status == model.TaskStatusFailed || status == model.TaskStatusCancelled {
			if err := FinalizeAssetDiscoveryAfterScan(r.db, &r.task); err != nil {
				slog.Warn("[Runner] 资产探测收尾失败", "task_id", r.task.ID, "error", err)
			}
		}
	case model.TaskTypeVulnRetest:
		if status == model.TaskStatusCompleted || status == model.TaskStatusPartial {
			if err := RecordRetestExecutionMeta(r.db, &r.task); err != nil {
				slog.Warn("[Runner] 回测元数据写入失败", "task_id", r.task.ID, "error", err)
			}
			if err := ApplyVulnRetestFromTask(r.db, &r.task); err != nil {
				slog.Warn("[Runner] 漏洞回测结果处理失败", "task_id", r.task.ID, "error", err)
			}
		}
	default:
		if status == model.TaskStatusCompleted || status == model.TaskStatusPartial || status == model.TaskStatusFailed {
			if n, err := SyncVulnerabilitiesFromTask(r.db, &r.task); err != nil {
				slog.Warn("[Runner] 同步漏洞库失败", "task_id", r.task.ID, "error", err)
			} else if n > 0 {
				slog.Info("[Runner] 已同步漏洞到漏洞库", "task_id", r.task.ID, "count", n)
			}
		}
		if r.eventBridge != nil &&
			(status == model.TaskStatusCompleted || status == model.TaskStatusFailed ||
				status == model.TaskStatusPartial || status == model.TaskStatusCancelled) {
			r.eventBridge.OnScanComplete(ctx, r.task.ID)
		}
	}
}
