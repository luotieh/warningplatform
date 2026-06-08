package scanrunner

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"code.yt-security.com/public/scanengine/core"

	"vulnscan-backend/model"
)

// DBPersistAdapter implements scanengine/core.PersistCallback by writing to the database.
type DBPersistAdapter struct {
	db       *gorm.DB
	eventBus *EventBus
}

func NewDBPersistAdapter(db *gorm.DB, eventBus *EventBus) *DBPersistAdapter {
	return &DBPersistAdapter{db: db, eventBus: eventBus}
}

func (a *DBPersistAdapter) SaveFinding(ctx context.Context, taskID string, finding *core.Finding) error {
	var task model.ScanTask
	if err := a.db.Where("id = ?", taskID).First(&task).Error; err != nil {
		return err
	}
	rec := findingToRecord(task, finding)
	return a.db.Create(&rec).Error
}

func (a *DBPersistAdapter) SaveTargets(ctx context.Context, taskID string, targets []*core.Target) error {
	slog.Debug("[DBPersistAdapter] SaveTargets", "task_id", taskID, "count", len(targets))
	return nil
}

func (a *DBPersistAdapter) UpdateProgress(ctx context.Context, taskID string, progress core.Progress) error {
	return a.db.Model(&model.ScanTask{}).
		Where("id = ?", taskID).
		Updates(map[string]interface{}{
			"progress": progress.Percent,
		}).Error
}

func (a *DBPersistAdapter) MarkTaskComplete(ctx context.Context, taskID string, summary core.TaskSummary) error {
	return a.db.Model(&model.ScanTask{}).
		Where("id = ?", taskID).
		Updates(map[string]interface{}{
			"status":         model.TaskStatusCompleted,
			"total_findings": summary.TotalFindings,
		}).Error
}

func (a *DBPersistAdapter) MarkTaskFailed(ctx context.Context, taskID string, err error) error {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return a.db.Model(&model.ScanTask{}).
		Where("id = ?", taskID).
		Updates(map[string]interface{}{
			"status":  model.TaskStatusFailed,
			"message": msg,
		}).Error
}

// EventBusAdapter implements scanengine/core.EventCallback by forwarding to EventBus.
type EventBusAdapter struct {
	eventBus *EventBus
}

func NewEventBusAdapter(eventBus *EventBus) *EventBusAdapter {
	return &EventBusAdapter{eventBus: eventBus}
}

func (a *EventBusAdapter) OnFindingCreated(ctx context.Context, taskID string, finding *core.Finding) {
	if a.eventBus == nil {
		return
	}
	raw, _ := json.Marshal(finding)
	a.eventBus.Publish(taskID, ScanEvent{
		Type:    EventFinding,
		TaskID:  taskID,
		Payload: raw,
		Time:    time.Now(),
	})
}

func (a *EventBusAdapter) OnTaskStarted(ctx context.Context, taskID string) {
	if a.eventBus == nil {
		return
	}
	raw, _ := json.Marshal(map[string]string{"status": "running"})
	a.eventBus.Publish(taskID, ScanEvent{
		Type:    EventStage,
		TaskID:  taskID,
		Payload: raw,
		Time:    time.Now(),
	})
}

func (a *EventBusAdapter) OnTaskComplete(ctx context.Context, taskID string, summary core.TaskSummary) {
	if a.eventBus == nil {
		return
	}
	raw, _ := json.Marshal(DonePayload{Status: model.TaskStatusCompleted})
	a.eventBus.Publish(taskID, ScanEvent{
		Type:    EventDone,
		TaskID:  taskID,
		Payload: raw,
		Time:    time.Now(),
	})
}

func (a *EventBusAdapter) OnModuleComplete(ctx context.Context, taskID string, moduleID string, result *core.ModuleResult) {
	if a.eventBus == nil {
		return
	}
	raw, _ := json.Marshal(map[string]string{"module_id": moduleID, "status": "complete"})
	a.eventBus.Publish(taskID, ScanEvent{
		Type:    EventProgress,
		TaskID:  taskID,
		Payload: raw,
		Time:    time.Now(),
	})
}
