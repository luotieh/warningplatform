package scanrunner

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/core"
)

func (r *Runner) persistFindings() {
	findings := r.progress.GetFindings()

	if len(findings) == 0 {
		return
	}

	if r.findingFilter != nil {
		before := len(findings)
		findings = r.findingFilter.FilterFindings(findings)
		if filtered := before - len(findings); filtered > 0 {
			slog.Info("[Persist] 过滤规则命中",
				"task_id", r.task.ID,
				"filtered", filtered,
				"remaining", len(findings),
			)
		}
		if len(findings) == 0 {
			return
		}
	}

	assetResolver := BuildAssetIDResolver(&r.task)

	var records []model.ScanFinding
	reconCount, vulnCount := 0, 0

	r.persistMu.Lock()
	for _, f := range findings {
		if r.enginePolicy.MaxFindingsPersisted > 0 && int(r.persistedFindingCount.Load()) >= r.enginePolicy.MaxFindingsPersisted {
			slog.Info("[Persist] 已达 engine.max_findings 上限，停止批量持久化",
				"task_id", r.task.ID, "limit", r.enginePolicy.MaxFindingsPersisted)
			break
		}
		if !r.enginePolicy.AllowPersistFinding(f) {
			continue
		}
		dedupKey := computeDedupKey(r.task.ID, f, r.enginePolicy.StrictDedup)
		if _, ok := r.persistedKeys[dedupKey]; ok {
			continue
		}
		r.persistedKeys[dedupKey] = struct{}{}

		rec := findingToRecord(r.task, f)
		rec.AssetID = assetResolver.Resolve(rec.Target, rec.Port)
		records = append(records, rec)
		r.persistedFindingCount.Add(1)

		if rec.Category == model.FindingCategoryRecon {
			reconCount++
		} else {
			vulnCount++
		}
	}
	r.persistMu.Unlock()

	if len(records) == 0 {
		return
	}

	created := r.batchPersistFindings(records)

	slog.Info("[Persist] 扫描发现已持久化",
		"task_id", r.task.ID,
		"total", len(records),
		"recon", reconCount,
		"vuln", vulnCount,
		"created", created,
	)

	r.writebackServiceToPortOpen(records)
}

func (r *Runner) writebackServiceToPortOpen(records []model.ScanFinding) {
	var serviceRecords []model.ScanFinding
	for _, rec := range records {
		if rec.Type == "service" && rec.Port > 0 && rec.Target != "" {
			serviceRecords = append(serviceRecords, rec)
		}
	}
	if len(serviceRecords) == 0 {
		return
	}

	updated := 0
	for _, svc := range serviceRecords {
		svcData := svc.Data
		svcName, _ := svcData["service"].(string)
		version, _ := svcData["version"].(string)
		banner, _ := svcData["banner"].(string)
		if svcName == "" && version == "" {
			continue
		}

		var portFinding model.ScanFinding
		err := r.db.Where("task_id = ? AND target = ? AND port = ? AND type = ?",
			svc.TaskID, svc.Target, svc.Port, "port_open").
			First(&portFinding).Error
		if err != nil {
			continue
		}

		data := portFinding.Data
		if data == nil {
			data = model.JSONMap{}
		}
		changed := false
		if svcName != "" && data["service"] == nil {
			data["service"] = svcName
			changed = true
		}
		if version != "" && data["version"] == nil {
			data["version"] = version
			changed = true
		}
		if banner != "" && data["banner"] == nil {
			data["banner"] = banner
			changed = true
		}
		if !changed {
			continue
		}
		if err := r.db.Model(&model.ScanFinding{}).
			Where("id = ?", portFinding.ID).
			Update("data", data).Error; err != nil {
			slog.Warn("[Persist] 回写服务信息到port_open失败",
				"finding_id", portFinding.ID, "error", err)
		} else {
			updated++
		}
	}

	if updated > 0 {
		slog.Info("[Persist] 服务探测结果已回写到端口发现",
			"task_id", r.task.ID, "updated", updated)
	}
}

func findingToRecord(task model.ScanTask, f *core.Finding) model.ScanFinding {
	target := ""
	port := 0
	protocol := ""
	if f.Target != nil {
		target = f.Target.Host
		if target == "" && f.Target.IP != "" {
			target = f.Target.IP
		}
		if target == "" && f.Target.URL != "" {
			target = extractHostFromURL(f.Target.URL)
		}
		port = f.Target.Port
		protocol = f.Target.Protocol
	}

	severity := f.Severity
	if severity == "" {
		severity = "info"
	}

	category := model.InferFindingCategory(f.ModuleID, f.Type)

	data := model.JSONMap{}
	for k, v := range f.Data {
		data[k] = v
	}

	verificationLevel := string(f.VerificationLevel)
	if verificationLevel == "" {
		verificationLevel = "principle"
	}

	return model.ScanFinding{
		ID:                 qulid.GenerateID(),
		TaskID:             task.ID,
		ModuleID:           f.ModuleID,
		Type:               f.Type,
		Category:           category,
		Target:             target,
		Port:               port,
		Protocol:           protocol,
		Title:              f.Title,
		Description:        f.Description,
		Severity:           severity,
		Confidence:         f.Confidence,
		ConfidenceReason:   f.ConfidenceReason,
		Evidence:           f.Evidence,
		VerificationLevel:  verificationLevel,
		VerificationDetail: f.VerificationDetail,
		Data:               data,
		CreatedAt:          time.Now(),
	}
}

func extractHostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := u.Hostname()
	if host != "" {
		return host
	}
	return rawURL
}

func computeDedupKey(taskID string, f *core.Finding, strict bool) string {
	if f == nil {
		return ""
	}
	target := ""
	port := 0
	protocol := ""
	typeStr := f.Type
	sev := f.Severity
	if f.Target != nil {
		target = f.Target.Host + f.Target.IP + f.Target.URL
		port = f.Target.Port
		protocol = f.Target.Protocol
	}
	raw := fmt.Sprintf("%s|%s|%d|%s|%s|%s", taskID, target, port, protocol, f.ModuleID, f.Title)
	if strict {
		raw += fmt.Sprintf("|%s|%s", typeStr, sev)
	}
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash[:16])
}
