package scanrunner

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

type DeltaScanEngine struct {
	db *gorm.DB
}

func NewDeltaScanEngine(db *gorm.DB) *DeltaScanEngine {
	return &DeltaScanEngine{db: db}
}

type DeltaResult struct {
	TaskID       string         `json:"task_id"`
	BaseTaskID   string         `json:"base_task_id"`
	NewFindings  []DeltaFinding `json:"new_findings"`
	GoneFindings []DeltaFinding `json:"gone_findings"`
	Changed      []DeltaFinding `json:"changed"`
	Summary      DeltaSummary   `json:"summary"`
}

type DeltaFinding struct {
	ID       string `json:"id"`
	ModuleID string `json:"module_id"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Type     string `json:"type"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}

type DeltaSummary struct {
	TotalCurrent  int `json:"total_current"`
	TotalBaseline int `json:"total_baseline"`
	NewCount      int `json:"new_count"`
	GoneCount     int `json:"gone_count"`
	ChangedCount  int `json:"changed_count"`
	RiskDelta     int `json:"risk_delta"`
}

func (d *DeltaScanEngine) Compare(currentTaskID, baseTaskID string) (*DeltaResult, error) {
	var currentFindings, baseFindings []model.ScanFinding
	if err := d.db.Where("task_id = ?", currentTaskID).Find(&currentFindings).Error; err != nil {
		return nil, fmt.Errorf("查询当前任务结果失败: %w", err)
	}
	if err := d.db.Where("task_id = ?", baseTaskID).Find(&baseFindings).Error; err != nil {
		return nil, fmt.Errorf("查询基线任务结果失败: %w", err)
	}

	baseIndex := make(map[string]model.ScanFinding)
	for _, f := range baseFindings {
		key := findingKey(f)
		baseIndex[key] = f
	}

	currentIndex := make(map[string]model.ScanFinding)
	for _, f := range currentFindings {
		key := findingKey(f)
		currentIndex[key] = f
	}

	result := &DeltaResult{
		TaskID:     currentTaskID,
		BaseTaskID: baseTaskID,
	}

	for key, cf := range currentIndex {
		if bf, ok := baseIndex[key]; ok {
			if cf.Severity != bf.Severity {
				result.Changed = append(result.Changed, toDeltaFinding(cf, "severity_changed"))
			}
		} else {
			result.NewFindings = append(result.NewFindings, toDeltaFinding(cf, "new"))
		}
	}

	for key, bf := range baseIndex {
		if _, ok := currentIndex[key]; !ok {
			result.GoneFindings = append(result.GoneFindings, toDeltaFinding(bf, "gone"))
		}
	}

	result.Summary = DeltaSummary{
		TotalCurrent:  len(currentFindings),
		TotalBaseline: len(baseFindings),
		NewCount:      len(result.NewFindings),
		GoneCount:     len(result.GoneFindings),
		ChangedCount:  len(result.Changed),
		RiskDelta:     calcRiskDelta(result.NewFindings, result.GoneFindings),
	}

	slog.Info("[DeltaScan] 差异比对完成",
		"current", currentTaskID,
		"base", baseTaskID,
		"new", result.Summary.NewCount,
		"gone", result.Summary.GoneCount,
	)

	return result, nil
}

func (d *DeltaScanEngine) FindBaseline(targets []string) (string, error) {
	return d.FindBaselineByTemplate(targets, "")
}

func (d *DeltaScanEngine) FindBaselineByTemplate(targets []string, templateID string) (string, error) {
	query := d.db.Where("status = 'completed'").Order("finished_at DESC").Limit(20)
	if strings.TrimSpace(templateID) != "" {
		query = query.Where("template_id = ?", templateID)
	}

	var candidates []model.ScanTask
	if err := query.Find(&candidates).Error; err != nil || len(candidates) == 0 {
		return "", fmt.Errorf("无基线任务: %w", err)
	}

	inputSet := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		inputSet[t] = struct{}{}
	}

	bestID := ""
	bestScore := 0.0

	for _, task := range candidates {
		taskTargetSet := make(map[string]struct{}, len(task.Targets))
		for _, t := range task.Targets {
			taskTargetSet[t] = struct{}{}
		}

		overlap := 0
		for _, t := range targets {
			if _, ok := taskTargetSet[t]; ok {
				overlap++
			}
		}
		if overlap == 0 {
			continue
		}

		union := len(inputSet)
		for t := range taskTargetSet {
			if _, ok := inputSet[t]; !ok {
				union++
			}
		}
		jaccard := float64(overlap) / float64(union)

		if jaccard > bestScore {
			bestScore = jaccard
			bestID = task.ID
		}
	}

	if bestID == "" {
		return "", fmt.Errorf("无重叠目标的基线任务")
	}

	return bestID, nil
}

func (d *DeltaScanEngine) Timeline(target string, limit int) ([]TimelineEntry, error) {
	if limit <= 0 {
		limit = 20
	}

	var findings []model.ScanFinding
	err := d.db.Where("target = ?", target).
		Order("created_at DESC").
		Limit(limit).
		Find(&findings).Error
	if err != nil {
		return nil, err
	}

	var entries []TimelineEntry
	for _, f := range findings {
		entries = append(entries, TimelineEntry{
			TaskID:    f.TaskID,
			Timestamp: f.CreatedAt,
			Type:      f.Type,
			Title:     f.Title,
			Severity:  f.Severity,
			ModuleID:  f.ModuleID,
		})
	}

	return entries, nil
}

type TimelineEntry struct {
	TaskID    string    `json:"task_id"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	ModuleID  string    `json:"module_id"`
}

func findingKey(f model.ScanFinding) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s",
		strings.ToLower(f.Target),
		f.ModuleID,
		f.Port,
		f.Type,
		strings.ToLower(f.Title),
	)
}

func toDeltaFinding(f model.ScanFinding, status string) DeltaFinding {
	return DeltaFinding{
		ID:       f.ID,
		ModuleID: f.ModuleID,
		Target:   f.Target,
		Port:     f.Port,
		Type:     f.Type,
		Title:    f.Title,
		Severity: f.Severity,
		Status:   status,
	}
}

func calcRiskDelta(newFindings, goneFindings []DeltaFinding) int {
	severityScore := map[string]int{
		"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0,
	}

	delta := 0
	for _, f := range newFindings {
		delta += severityScore[f.Severity]
	}
	for _, f := range goneFindings {
		delta -= severityScore[f.Severity]
	}
	return delta
}
