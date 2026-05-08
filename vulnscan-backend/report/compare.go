package report

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type CompareResult struct {
	BaseTaskID     string         `json:"base_task_id"`
	CompareTaskID  string         `json:"compare_task_id"`
	NewVulns       []VulnDiff     `json:"new_vulns"`
	FixedVulns     []VulnDiff     `json:"fixed_vulns"`
	ChangedVulns   []VulnDiff     `json:"changed_vulns"`
	UnchangedCount int            `json:"unchanged_count"`
	Summary        CompareSummary `json:"summary"`
}

type VulnDiff struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Target      string `json:"target"`
	Status      string `json:"status"`
	OldSeverity string `json:"old_severity,omitempty"`
	DiffType    string `json:"diff_type"`
}

type CompareSummary struct {
	BaseTotal    int `json:"base_total"`
	CompareTotal int `json:"compare_total"`
	NewCount     int `json:"new_count"`
	FixedCount   int `json:"fixed_count"`
	ChangedCount int `json:"changed_count"`
	Delta        int `json:"delta"`
}

func CompareTasks(db *gorm.DB, baseTaskID, compareTaskID string) (*CompareResult, error) {
	var baseVulns []model.Vulnerability
	db.Where("task_id = ?", baseTaskID).Find(&baseVulns)

	var compareVulns []model.Vulnerability
	db.Where("task_id = ?", compareTaskID).Find(&compareVulns)

	baseMap := make(map[string]*model.Vulnerability, len(baseVulns))
	for i := range baseVulns {
		key := vulnKey(&baseVulns[i])
		baseMap[key] = &baseVulns[i]
	}

	compareMap := make(map[string]*model.Vulnerability, len(compareVulns))
	for i := range compareVulns {
		key := vulnKey(&compareVulns[i])
		compareMap[key] = &compareVulns[i]
	}

	result := &CompareResult{
		BaseTaskID:    baseTaskID,
		CompareTaskID: compareTaskID,
	}

	for key, cv := range compareMap {
		if bv, ok := baseMap[key]; ok {
			if bv.Severity != cv.Severity {
				result.ChangedVulns = append(result.ChangedVulns, VulnDiff{
					ID:          cv.ID,
					Title:       cv.Title,
					Severity:    cv.Severity,
					Target:      cv.Target,
					Status:      cv.Status,
					OldSeverity: bv.Severity,
					DiffType:    "changed",
				})
			} else {
				result.UnchangedCount++
			}
		} else {
			result.NewVulns = append(result.NewVulns, VulnDiff{
				ID:       cv.ID,
				Title:    cv.Title,
				Severity: cv.Severity,
				Target:   cv.Target,
				Status:   cv.Status,
				DiffType: "new",
			})
		}
	}

	for key, bv := range baseMap {
		if _, ok := compareMap[key]; !ok {
			result.FixedVulns = append(result.FixedVulns, VulnDiff{
				ID:       bv.ID,
				Title:    bv.Title,
				Severity: bv.Severity,
				Target:   bv.Target,
				Status:   bv.Status,
				DiffType: "fixed",
			})
		}
	}

	result.Summary = CompareSummary{
		BaseTotal:    len(baseVulns),
		CompareTotal: len(compareVulns),
		NewCount:     len(result.NewVulns),
		FixedCount:   len(result.FixedVulns),
		ChangedCount: len(result.ChangedVulns),
		Delta:        len(compareVulns) - len(baseVulns),
	}

	return result, nil
}

func vulnKey(v *model.Vulnerability) string {
	return v.Target + "|" + v.Title + "|" + v.ModuleID
}
