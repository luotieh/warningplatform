package scanrunner

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"gorm.io/gorm"
)

type Checkpoint struct {
	ID          string    `gorm:"primarykey;type:varchar(100)" json:"id"`
	TaskID      string    `gorm:"type:varchar(36);index;not null" json:"task_id"`
	Stage       string    `gorm:"type:varchar(50)" json:"stage"`
	ModuleID    string    `gorm:"type:varchar(50)" json:"module_id"`
	Status      string    `gorm:"type:varchar(20);default:'pending'" json:"status"`
	TargetsJSON string    `gorm:"type:text" json:"targets_json"`
	ResultJSON  string    `gorm:"type:text" json:"result_json"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (Checkpoint) TableName() string { return "vs_checkpoint" }

type CheckpointManager struct {
	db    *gorm.DB
	mu    sync.Mutex
	cache map[string]*Checkpoint
}

func NewCheckpointManager(db *gorm.DB) *CheckpointManager {
	db.AutoMigrate(&Checkpoint{})
	return &CheckpointManager{
		db:    db,
		cache: make(map[string]*Checkpoint),
	}
}

func (cm *CheckpointManager) SaveModuleStart(taskID, stage, moduleID string, targets []string) {
	cp := &Checkpoint{
		ID:        checkpointKey(taskID, stage, moduleID),
		TaskID:    taskID,
		Stage:     stage,
		ModuleID:  moduleID,
		Status:    "running",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if targetsJSON, err := json.Marshal(targets); err == nil {
		cp.TargetsJSON = string(targetsJSON)
	}

	cm.mu.Lock()
	cm.cache[cp.ID] = cp
	cm.mu.Unlock()

	cm.db.Save(cp)
}

func (cm *CheckpointManager) SaveModuleComplete(taskID, stage, moduleID string, findingCount, targetCount int) {
	key := checkpointKey(taskID, stage, moduleID)

	cm.mu.Lock()
	cp, ok := cm.cache[key]
	if !ok {
		cp = &Checkpoint{ID: key, TaskID: taskID, Stage: stage, ModuleID: moduleID}
		cm.cache[key] = cp
	}
	cm.mu.Unlock()

	cp.Status = "completed"
	cp.UpdatedAt = time.Now()

	result := map[string]int{
		"finding_count": findingCount,
		"target_count":  targetCount,
	}
	if data, err := json.Marshal(result); err == nil {
		cp.ResultJSON = string(data)
	}

	cm.db.Save(cp)
}

func (cm *CheckpointManager) SaveModuleFailed(taskID, stage, moduleID, errMsg string) {
	key := checkpointKey(taskID, stage, moduleID)

	cm.mu.Lock()
	cp, ok := cm.cache[key]
	if !ok {
		cp = &Checkpoint{ID: key, TaskID: taskID, Stage: stage, ModuleID: moduleID}
		cm.cache[key] = cp
	}
	cm.mu.Unlock()

	cp.Status = "failed"
	cp.UpdatedAt = time.Now()
	result := map[string]string{"error": errMsg}
	if data, err := json.Marshal(result); err == nil {
		cp.ResultJSON = string(data)
	}

	cm.db.Save(cp)
}

func (cm *CheckpointManager) IsModuleCompleted(taskID, stage, moduleID string) bool {
	key := checkpointKey(taskID, stage, moduleID)

	cm.mu.Lock()
	if cp, ok := cm.cache[key]; ok {
		cm.mu.Unlock()
		return cp.Status == "completed"
	}
	cm.mu.Unlock()

	var cp Checkpoint
	if err := cm.db.Where("id = ?", key).First(&cp).Error; err != nil {
		return false
	}

	cm.mu.Lock()
	cm.cache[key] = &cp
	cm.mu.Unlock()

	return cp.Status == "completed"
}

func (cm *CheckpointManager) GetCompletedStages(taskID string) []string {
	var checkpoints []Checkpoint
	cm.db.Where("task_id = ? AND status = 'completed'", taskID).Find(&checkpoints)

	stageComplete := make(map[string]bool)
	for _, cp := range checkpoints {
		stageComplete[cp.Stage] = true
	}

	var stages []string
	for s := range stageComplete {
		stages = append(stages, s)
	}
	return stages
}

func (cm *CheckpointManager) GetResumePoint(taskID string) (stage string, completedModules []string) {
	var checkpoints []Checkpoint
	cm.db.Where("task_id = ?", taskID).
		Order("created_at ASC").
		Find(&checkpoints)

	stageModules := make(map[string]map[string]string)
	var lastStage string

	for _, cp := range checkpoints {
		if _, ok := stageModules[cp.Stage]; !ok {
			stageModules[cp.Stage] = make(map[string]string)
		}
		stageModules[cp.Stage][cp.ModuleID] = cp.Status
		lastStage = cp.Stage
	}

	stage = lastStage
	if mods, ok := stageModules[stage]; ok {
		for modID, status := range mods {
			if status == "completed" {
				completedModules = append(completedModules, modID)
			}
		}
	}

	return stage, completedModules
}

func (cm *CheckpointManager) ClearTask(taskID string) {
	cm.db.Where("task_id = ?", taskID).Delete(&Checkpoint{})

	cm.mu.Lock()
	for key, cp := range cm.cache {
		if cp.TaskID == taskID {
			delete(cm.cache, key)
		}
	}
	cm.mu.Unlock()

	slog.Info("[Checkpoint] 已清除任务checkpoint", "task", taskID)
}

func checkpointKey(taskID, stage, moduleID string) string {
	return fmt.Sprintf("%s|%s|%s", taskID, stage, moduleID)
}
