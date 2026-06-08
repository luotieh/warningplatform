package scanrunner

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"code.yt-security.com/public/core/generate/ulid"

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
		"vuln_retest":    true,
	}
	if tid := strings.TrimSpace(vuln.TemplateID); tid != "" {
		params["poc_template_ids"] = []string{tid}
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
	if u := extractMatchedURLFromEvidence(v.Evidence); u != "" {
		return u
	}
	host := strings.TrimSpace(v.Target)
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		return host
	}
	if v.Port > 0 && !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, v.Port)
	}
	return host
}

func extractMatchedURLFromEvidence(evidence string) string {
	for _, line := range strings.Split(evidence, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "matched:") {
			if i := strings.Index(line, ":"); i >= 0 && i < len(line)-1 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func truncateRunes(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max]) + "…"
}

// RecordRetestExecutionMeta 在回测任务结束后写入 parameters，供结果判定使用。
func RecordRetestExecutionMeta(db *gorm.DB, task *model.ScanTask) error {
	if db == nil || task == nil {
		return nil
	}
	var logs []model.ScanLog
	_ = db.Where("task_id = ?", task.ID).Order("created_at ASC").Find(&logs).Error

	skipped := false
	executed := false
	templateCount := 0
	for _, log := range logs {
		msg := log.Message
		if strings.Contains(msg, "无PoC模板") ||
			strings.Contains(msg, "无有效模板路径") ||
			strings.Contains(msg, "回测未找到可用 PoC") {
			skipped = true
		}
		if strings.Contains(msg, "开始Nuclei扫描") {
			executed = true
			if i := strings.Index(msg, "template_sources"); i >= 0 {
				var n int
				_, _ = fmt.Sscanf(msg[i:], "template_sources %d", &n)
				if n > 0 {
					templateCount = n
				}
			}
		}
	}

	var findingCount int64
	_ = db.Model(&model.ScanFinding{}).
		Where("task_id = ? AND category = ?", task.ID, model.FindingCategoryVuln).
		Count(&findingCount).Error

	params := task.Parameters
	if params == nil {
		params = model.JSONMap{}
	}
	params["retest_poc_skipped"] = skipped
	params["retest_poc_executed"] = executed && !skipped
	params["retest_template_count"] = templateCount
	params["retest_vuln_findings"] = findingCount

	return db.Model(&model.ScanTask{}).Where("id = ?", task.ID).Update("parameters", params).Error
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

	if boolParam(task.Parameters, "retest_poc_skipped") || !boolParam(task.Parameters, "retest_poc_executed") {
		writeVulnHistory(db, vulnID, vuln.Status, vuln.Status,
			fmt.Sprintf("回测未完成（任务 %s）：PoC 未实际执行，状态未变更", task.ID), task.CreatedBy)
		slog.Warn("[VulnRetest] PoC 未执行，跳过状态更新", "vuln_id", vulnID, "task_id", task.ID)
		return nil
	}

	var findings []model.ScanFinding
	if err := db.Where("task_id = ? AND category = ?", task.ID, model.FindingCategoryVuln).Find(&findings).Error; err != nil {
		return err
	}

	matched := matchRetestFinding(findings, &vuln, task)
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

	// 指定了 PoC 且已执行扫描、无匹配结果 → 认为未复现
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

func matchRetestFinding(findings []model.ScanFinding, vuln *model.Vulnerability, task *model.ScanTask) *model.ScanFinding {
	expectedTpl := strings.TrimSpace(vuln.TemplateID)
	if expectedTpl == "" && task != nil {
		if ids := stringSliceParam(task.Parameters, "poc_template_ids"); len(ids) == 1 {
			expectedTpl = ids[0]
		}
	}

	for i := range findings {
		f := &findings[i]
		if !sameRetestTarget(f, vuln) {
			continue
		}
		ftpl := findingTemplateID(f)
		if expectedTpl != "" && ftpl != "" && strings.EqualFold(ftpl, expectedTpl) {
			return f
		}
		if strings.EqualFold(strings.TrimSpace(f.Title), strings.TrimSpace(vuln.Title)) {
			return f
		}
	}
	// 单模板回测：同目标上任意 nuclei 漏洞类发现视为复现
	if expectedTpl != "" {
		for i := range findings {
			f := &findings[i]
			if f.ModuleID == "nuclei-poc" && sameRetestTarget(f, vuln) {
				return f
			}
		}
	}
	return nil
}

func sameRetestTarget(f *model.ScanFinding, v *model.Vulnerability) bool {
	fh := normalizeRetestHost(f.Target, f.Port)
	vh := normalizeRetestHost(v.Target, v.Port)
	if fh == "" || vh == "" {
		return false
	}
	return fh == vh || strings.HasPrefix(fh, vh+":") || strings.HasPrefix(vh, fh+":")
}

func normalizeRetestHost(target string, port int) string {
	s := strings.TrimSpace(strings.ToLower(target))
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return s
		}
		host := strings.ToLower(u.Hostname())
		if p := u.Port(); p != "" {
			return host + ":" + p
		}
		if port > 0 {
			return fmt.Sprintf("%s:%d", host, port)
		}
		return host
	}
	if h, p, err := splitHostPort(s); err == nil {
		if p != "" {
			return h + ":" + p
		}
		return h
	}
	if port > 0 && !strings.Contains(s, ":") {
		return fmt.Sprintf("%s:%d", s, port)
	}
	return s
}

func splitHostPort(hostport string) (host, port string, err error) {
	if strings.HasPrefix(hostport, "[") {
		return "", "", fmt.Errorf("skip")
	}
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return hostport, "", nil
	}
	return hostport[:i], hostport[i+1:], nil
}

func findingTemplateID(f *model.ScanFinding) string {
	if f.Data == nil {
		return ""
	}
	if v := jsonMapString(f.Data, "template_id"); v != "" {
		return v
	}
	return jsonMapString(f.Data, "poc_id")
}

func jsonMapString(m model.JSONMap, key string) string {
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

func boolParam(m model.JSONMap, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true" || b == "1"
	default:
		return false
	}
}

func stringSliceParam(m model.JSONMap, key string) []string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch arr := v.(type) {
	case []string:
		return arr
	case []interface{}:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
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
		ID:        ulid.GenerateID(),
		VulnID:    vulnID,
		OldStatus: oldStatus,
		NewStatus: newStatus,
		Comment:   comment,
		Operator:  operator,
	}).Error
}
