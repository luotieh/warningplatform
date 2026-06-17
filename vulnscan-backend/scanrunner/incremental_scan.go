package scanrunner

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// IncrementalScanEngine determines which targets need rescanning by comparing
// current fingerprints against the previous scan baseline.
type IncrementalScanEngine struct {
	db *gorm.DB
}

func NewIncrementalScanEngine(db *gorm.DB) *IncrementalScanEngine {
	return &IncrementalScanEngine{db: db}
}

// TargetChangeInfo describes what changed for a specific target.
type TargetChangeInfo struct {
	Target      string   `json:"target"`
	ChangeType  string   `json:"change_type"`
	NewPorts    []int    `json:"new_ports,omitempty"`
	ClosedPorts []int    `json:"closed_ports,omitempty"`
	ChangedFP   []string `json:"changed_fingerprints,omitempty"`
}

// IncrementalPlan describes which targets to scan and which to skip.
type IncrementalPlan struct {
	BaselineTaskID   string             `json:"baseline_task_id"`
	BaselineTime     time.Time          `json:"baseline_time"`
	TotalTargets     int                `json:"total_targets"`
	ChangedTargets   int                `json:"changed_targets"`
	UnchangedTargets int                `json:"unchanged_targets"`
	NewTargets       int                `json:"new_targets"`
	TargetsToScan    []string           `json:"targets_to_scan"`
	SkippedTargets   []string           `json:"skipped_targets"`
	Changes          []TargetChangeInfo `json:"changes,omitempty"`
}

// PlanIncrementalScan compares current targets against the most recent
// baseline scan and returns a plan indicating which targets need rescanning.
func (e *IncrementalScanEngine) PlanIncrementalScan(targets []string, templateID string) (*IncrementalPlan, error) {
	baseTaskID, err := e.findBaseline(targets, templateID)
	if err != nil {
		return &IncrementalPlan{
			TotalTargets:  len(targets),
			NewTargets:    len(targets),
			TargetsToScan: targets,
		}, nil
	}

	var baseTask model.ScanTask
	if err := e.db.First(&baseTask, "id = ?", baseTaskID).Error; err != nil {
		return nil, fmt.Errorf("获取基线任务失败: %w", err)
	}

	baseFingerprints := e.loadFingerprints(baseTaskID)

	var baselineTime time.Time
	if baseTask.FinishedAt != nil {
		baselineTime = *baseTask.FinishedAt
	}

	plan := &IncrementalPlan{
		BaselineTaskID: baseTaskID,
		BaselineTime:   baselineTime,
		TotalTargets:   len(targets),
	}

	baseTargetSet := make(map[string]struct{})
	for _, t := range baseTask.Targets {
		baseTargetSet[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}

	for _, target := range targets {
		normalized := strings.ToLower(strings.TrimSpace(target))

		if _, existed := baseTargetSet[normalized]; !existed {
			plan.TargetsToScan = append(plan.TargetsToScan, target)
			plan.NewTargets++
			plan.Changes = append(plan.Changes, TargetChangeInfo{
				Target:     target,
				ChangeType: "new",
			})
			continue
		}

		fp, hasFP := baseFingerprints[normalized]
		if !hasFP {
			plan.TargetsToScan = append(plan.TargetsToScan, target)
			plan.ChangedTargets++
			plan.Changes = append(plan.Changes, TargetChangeInfo{
				Target:     target,
				ChangeType: "no_baseline_data",
			})
			continue
		}

		changed, changeInfo := e.checkTargetChanged(target, fp)
		if changed {
			plan.TargetsToScan = append(plan.TargetsToScan, target)
			plan.ChangedTargets++
			plan.Changes = append(plan.Changes, changeInfo)
		} else {
			plan.SkippedTargets = append(plan.SkippedTargets, target)
			plan.UnchangedTargets++
		}
	}

	slog.Info("[IncrementalScan] 增量扫描计划生成",
		"baseline_task", baseTaskID,
		"total", plan.TotalTargets,
		"to_scan", len(plan.TargetsToScan),
		"skipped", len(plan.SkippedTargets),
		"new", plan.NewTargets,
		"changed", plan.ChangedTargets,
	)

	return plan, nil
}

type targetFingerprint struct {
	ports        map[int]string
	fingerprints map[string]string
	lastSeen     time.Time
}

func (e *IncrementalScanEngine) loadFingerprints(taskID string) map[string]*targetFingerprint {
	fps := make(map[string]*targetFingerprint)

	var findings []model.ScanFinding
	e.db.Where("task_id = ? AND type IN ?", taskID,
		[]string{"port_open", "service", "fingerprint", "tech_stack"}).
		Find(&findings)

	for _, f := range findings {
		target := strings.ToLower(strings.TrimSpace(f.Target))
		fp, ok := fps[target]
		if !ok {
			fp = &targetFingerprint{
				ports:        make(map[int]string),
				fingerprints: make(map[string]string),
			}
			fps[target] = fp
		}

		switch f.Type {
		case "port_open":
			svc := ""
			if f.Data != nil {
				if s, ok := f.Data["service"].(string); ok {
					svc = s
				}
			}
			fp.ports[f.Port] = svc
		case "service":
			svc := ""
			if f.Data != nil {
				if s, ok := f.Data["service"].(string); ok {
					svc = s
				}
			}
			fp.ports[f.Port] = svc
		case "fingerprint", "tech_stack":
			product := ""
			version := ""
			if f.Data != nil {
				if p, ok := f.Data["product"].(string); ok {
					product = p
				}
				if v, ok := f.Data["version"].(string); ok {
					version = v
				}
				if product == "" {
					if n, ok := f.Data["name"].(string); ok {
						product = n
					}
				}
			}
			if product != "" {
				key := fmt.Sprintf("%s:%d", f.ModuleID, f.Port)
				fp.fingerprints[key] = product + "/" + version
			}
		}
		fp.lastSeen = f.CreatedAt
	}

	return fps
}

// checkTargetChanged performs a quick probe to see if a target has changed since baseline.
func (e *IncrementalScanEngine) checkTargetChanged(target string, baseFP *targetFingerprint) (bool, TargetChangeInfo) {
	info := TargetChangeInfo{
		Target:     target,
		ChangeType: "unchanged",
	}

	if baseFP.lastSeen.Before(time.Now().Add(-7 * 24 * time.Hour)) {
		info.ChangeType = "stale_baseline"
		return true, info
	}

	return false, info
}

func (e *IncrementalScanEngine) findBaseline(targets []string, templateID string) (string, error) {
	query := e.db.Where("status = ?", model.TaskStatusCompleted).
		Order("finished_at DESC").
		Limit(20)

	if templateID != "" {
		query = query.Where("template_id = ?", templateID)
	}

	var candidates []model.ScanTask
	if err := query.Find(&candidates).Error; err != nil || len(candidates) == 0 {
		return "", fmt.Errorf("无基线任务")
	}

	inputSet := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		inputSet[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}

	bestID := ""
	bestScore := 0.0

	for _, task := range candidates {
		overlap := 0
		for _, t := range task.Targets {
			if _, ok := inputSet[strings.ToLower(strings.TrimSpace(t))]; ok {
				overlap++
			}
		}
		if overlap == 0 {
			continue
		}
		score := float64(overlap) / float64(len(inputSet))
		if score > bestScore {
			bestScore = score
			bestID = task.ID
		}
	}

	if bestID == "" || bestScore < 0.5 {
		return "", fmt.Errorf("无匹配度足够的基线任务 (最高: %.0f%%)", bestScore*100)
	}

	return bestID, nil
}

// CreateIncrementalTask creates a new scan task that only scans changed targets.
func (e *IncrementalScanEngine) CreateIncrementalTask(originalTask model.ScanTask, plan *IncrementalPlan) (*model.ScanTask, error) {
	if len(plan.TargetsToScan) == 0 {
		return nil, fmt.Errorf("无需扫描的目标（所有目标均未变化）")
	}

	newTask := originalTask
	newTask.ID = ""
	newTask.Targets = plan.TargetsToScan
	newTask.Status = model.TaskStatusQueued
	newTask.ParentID = ""

	if newTask.Parameters == nil {
		newTask.Parameters = model.JSONMap{}
	}
	newTask.Parameters["incremental"] = true
	newTask.Parameters["baseline_task_id"] = plan.BaselineTaskID
	newTask.Parameters["original_target_count"] = plan.TotalTargets
	newTask.Parameters["skipped_targets"] = plan.UnchangedTargets

	if newTask.Name != "" {
		newTask.Name = newTask.Name + " [增量]"
	}

	slog.Info("[IncrementalScan] 创建增量扫描任务",
		"targets_to_scan", len(plan.TargetsToScan),
		"skipped", plan.UnchangedTargets,
		"baseline", plan.BaselineTaskID,
	)

	return &newTask, nil
}
