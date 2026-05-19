package scanrunner

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

const VulnRetestTemplateID = "vuln-retest"

// LaunchVulnRetest 对单条漏洞发起 PoC 回测扫描。
func LaunchVulnRetest(db *gorm.DB, sched *Scheduler, vuln *model.Vulnerability, createdBy, organizeID string) (*LaunchScanResult, error) {
	if db == nil || sched == nil || vuln == nil {
		return nil, fmt.Errorf("invalid retest params")
	}
	target := buildRetestTarget(vuln)
	if target == "" {
		return nil, fmt.Errorf("漏洞目标为空，无法回测")
	}

	name := fmt.Sprintf("漏洞回测: %s", truncateRunes(vuln.Title, 40))
	params := map[string]interface{}{
		"source_vuln_id": vuln.ID,
	}
	if strings.TrimSpace(vuln.TemplateID) != "" {
		params["poc_template_ids"] = []string{vuln.TemplateID}
	}

	launch := LaunchScanParams{
		Name:       name,
		Targets:    []string{target},
		TemplateID: VulnRetestTemplateID,
		Priority:   7,
		CreatedBy:  createdBy,
		OrganizeID: organizeID,
		TaskType:   model.TaskTypeVulnRetest,
		Parameters: params,
	}
	if aid := strings.TrimSpace(vuln.AssetID); aid != "" {
		launch.AssetIDs = []string{aid}
	}
	return LaunchScan(db, sched, launch)
}

func buildRetestTarget(v *model.Vulnerability) string {
	host := strings.TrimSpace(v.Target)
	if host == "" {
		return ""
	}
	if v.Port > 0 && !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, v.Port)
	}
	return host
}

func truncateRunes(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max]) + "…"
}

// ApplyVulnRetestFromTask 根据回测任务结果更新原漏洞状态。
func ApplyVulnRetestFromTask(db *gorm.DB, task *model.ScanTask) error {
	if db == nil || task == nil || task.Type != model.TaskTypeVulnRetest {
		return nil
	}
	vulnID := stringParam(task.Parameters, "source_vuln_id")
	if vulnID == "" {
		return fmt.Errorf("missing source_vuln_id")
	}

	var vuln model.Vulnerability
	if err := db.First(&vuln, "id = ?", vulnID).Error; err != nil {
		return fmt.Errorf("source vuln not found: %w", err)
	}

	var findings []model.ScanFinding
	if err := db.Where("task_id = ? AND category = ?", task.ID, model.FindingCategoryVuln).Find(&findings).Error; err != nil {
		return err
	}

	matched := matchRetestFinding(findings, &vuln)
	now := time.Now()
	oldStatus := vuln.Status

	if matched != nil {
		updates := map[string]any{
			"status":      model.VulnStatusVerified,
			"verified_at": &now,
			"evidence":    matched.Evidence,
			"confidence":  matched.Confidence,
			"updated_at":  now,
			"fixed_at":    nil,
			"ignored_at":  nil,
		}
		if err := db.Model(&model.Vulnerability{}).Where("id = ?", vulnID).Updates(updates).Error; err != nil {
			return err
		}
		writeVulnHistory(db, vulnID, oldStatus, model.VulnStatusVerified,
			fmt.Sprintf("回测复现（任务 %s）", task.ID), task.CreatedBy)
		slog.Info("[VulnRetest] 漏洞仍可利用", "vuln_id", vulnID, "retest_task", task.ID)
		return nil
	}

	updates := map[string]any{
		"status":      model.VulnStatusFixed,
		"fixed_at":    &now,
		"updated_at":  now,
		"verified_at": &now,
	}
	if err := db.Model(&model.Vulnerability{}).Where("id = ?", vulnID).Updates(updates).Error; err != nil {
		return err
	}
	writeVulnHistory(db, vulnID, oldStatus, model.VulnStatusFixed,
		fmt.Sprintf("回测未复现，标记已修复（任务 %s）", task.ID), task.CreatedBy)
	slog.Info("[VulnRetest] 漏洞未复现", "vuln_id", vulnID, "retest_task", task.ID)
	return nil
}

func matchRetestFinding(findings []model.ScanFinding, vuln *model.Vulnerability) *model.ScanFinding {
	for i := range findings {
		f := &findings[i]
		if !sameRetestTarget(f, vuln) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(f.Title), strings.TrimSpace(vuln.Title)) {
			return f
		}
		if vuln.TemplateID != "" && f.Data != nil {
			if tid, ok := f.Data["template_id"].(string); ok && tid == vuln.TemplateID {
				return f
			}
		}
		if vuln.ModuleID != "" && f.ModuleID == vuln.ModuleID {
			return f
		}
	}
	return nil
}

func sameRetestTarget(f *model.ScanFinding, v *model.Vulnerability) bool {
	ft := strings.ToLower(strings.TrimSpace(f.Target))
	vt := strings.ToLower(strings.TrimSpace(v.Target))
	if ft == vt {
		return f.Port == 0 || v.Port == 0 || f.Port == v.Port
	}
	if v.Port > 0 {
		withPort := fmt.Sprintf("%s:%d", vt, v.Port)
		return ft == withPort
	}
	return false
}

func stringParam(m model.JSONMap, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return strings.TrimSpace(s)
	default:
		return strings.TrimSpace(fmt.Sprint(s))
	}
}

func writeVulnHistory(db *gorm.DB, vulnID, oldStatus, newStatus, comment, operator string) {
	_ = db.Create(&model.VulnStatusHistory{
		ID:        qulid.GenerateID(),
		VulnID:    vulnID,
		OldStatus: oldStatus,
		NewStatus: newStatus,
		Comment:   comment,
		Operator:  operator,
	}).Error
}
