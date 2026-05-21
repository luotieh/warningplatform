package scanrunner

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// DiscoveryScanTaskIDs 返回父任务及全部子任务 ID（用于聚合 findings）。
func DiscoveryScanTaskIDs(db *gorm.DB, rootTaskID string) []string {
	return discoveryScanTaskIDs(db, rootTaskID)
}

func discoveryScanTaskIDs(db *gorm.DB, rootTaskID string) []string {
	ids := []string{rootTaskID}
	var subs []model.ScanTask
	if err := db.Where("parent_id = ?", rootTaskID).Find(&subs).Error; err == nil {
		for _, s := range subs {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

// FinalizeAssetDiscoveryAfterScan 扫描结束后同步候选并更新探测记录状态。
func FinalizeAssetDiscoveryAfterScan(db *gorm.DB, task *model.ScanTask) error {
	if db == nil || task == nil || task.Type != model.TaskTypeAssetDiscovery {
		return nil
	}
	effectiveID := task.ID
	effectiveTask := task
	if pid := strings.TrimSpace(task.ParentID); pid != "" {
		var parent model.ScanTask
		if err := db.First(&parent, "id = ?", pid).Error; err != nil {
			return err
		}
		if !isScanTaskTerminalStatus(parent.Status) {
			return nil
		}
		effectiveID = pid
		effectiveTask = &parent
	} else if strings.TrimSpace(task.ParentID) == "" {
		var childCount int64
		_ = db.Model(&model.ScanTask{}).Where("parent_id = ?", task.ID).Count(&childCount).Error
		if childCount > 0 && !isScanTaskTerminalStatus(task.Status) {
			return nil
		}
	}

	var probe model.AssetDiscoveryProbe
	if err := db.Where("task_id = ?", effectiveID).First(&probe).Error; err != nil {
		probeID := discoveryProbeIDFromTaskParams(effectiveTask.Parameters)
		if probeID == "" {
			return nil
		}
		if err2 := db.First(&probe, "id = ?", probeID).Error; err2 != nil {
			return nil
		}
		if probe.TaskID == "" {
			_ = db.Model(&probe).Update("task_id", effectiveID).Error
		}
	}
	taskIDs := discoveryScanTaskIDs(db, effectiveID)
	if _, err := SyncAssetDiscoveryCandidates(db, probe.ID, taskIDs); err != nil {
		return err
	}
	return UpdateProbeStatusFromTask(db, &probe, effectiveTask)
}

// SyncAssetDiscoveryCandidates 根据扫描发现重建探测候选列表（支持父任务及子任务 findings）。
func SyncAssetDiscoveryCandidates(db *gorm.DB, probeID string, taskIDs []string) (int, error) {
	if db == nil || probeID == "" || len(taskIDs) == 0 {
		return 0, fmt.Errorf("invalid sync params")
	}

	var findings []model.ScanFinding
	if err := db.Where("task_id IN ?", taskIDs).
		Where("type IN ?", []string{"port_open", "host_alive", "service"}).
		Find(&findings).Error; err != nil {
		return 0, err
	}

	byHost := map[string]*model.AssetDiscoveryCandidate{}

	mergeDiscoveryCandidate := func(rawHost string, apply func(*model.AssetDiscoveryCandidate)) {
		canonical := DiscoveryCanonicalHost(rawHost)
		dedupKey := DiscoveryCandidateDedupKey(canonical)
		if dedupKey == "" {
			return
		}
		c := byHost[dedupKey]
		if c == nil {
			c = &model.AssetDiscoveryCandidate{
				ProbeID:   probeID,
				TaskID:    taskIDs[0],
				Address:   canonical,
				AssetType: discoveryAssetType(canonical),
				Status:    model.AssetDiscoveryCandidatePending,
			}
			byHost[dedupKey] = c
		}
		apply(c)
	}

	for i := range findings {
		f := findings[i]
		host := discoveryHostFromFinding(&f)
		if host == "" {
			continue
		}
		switch f.Type {
		case "host_alive":
			mergeDiscoveryCandidate(host, func(c *model.AssetDiscoveryCandidate) {
				c.Alive = true
				if strings.TrimSpace(c.Title) == "" {
					c.Title = "存活主机 " + c.Address
				}
				if c.Evidence == "" {
					c.Evidence = discoveryEvidence(&f)
				}
			})
		case "port_open", "service":
			port := f.Port
			if port == 0 {
				port = discoveryDataInt(f.Data, "port")
			}
			proto := strings.TrimSpace(f.Protocol)
			if proto == "" {
				proto = discoveryDataStr(f.Data, "protocol")
			}
			svc := discoveryDataStr(f.Data, "service")
			mergeDiscoveryCandidate(host, func(c *model.AssetDiscoveryCandidate) {
				c.Alive = true
				if port > 0 && c.Port == 0 {
					c.Port = port
					c.Protocol = proto
				}
				if svc != "" {
					if c.Service == "" {
						c.Service = svc
					}
					c.Title = fmt.Sprintf("检测到服务: %s", svc)
					if port > 0 {
						c.Title = fmt.Sprintf("检测到服务: %s (端口 %d)", svc, port)
					}
				} else if strings.TrimSpace(c.Title) == "" {
					if port > 0 {
						c.Title = fmt.Sprintf("开放端口 %s:%d", c.Address, port)
					}
				}
				if c.Evidence == "" {
					c.Evidence = discoveryEvidence(&f)
				}
			})
		}
	}

	imported := map[string]string{}
	var prior []model.AssetDiscoveryCandidate
	_ = db.Where("probe_id = ? AND status = ?", probeID, model.AssetDiscoveryCandidateImported).
		Find(&prior).Error
	for _, p := range prior {
		imported[DiscoveryCandidateDedupKey(p.Address)] = p.ImportedID
	}

	tx := db.Begin()
	if err := tx.Where("probe_id = ? AND status <> ?", probeID, model.AssetDiscoveryCandidateImported).
		Delete(&model.AssetDiscoveryCandidate{}).Error; err != nil {
		tx.Rollback()
		return 0, err
	}

	rows := make([]model.AssetDiscoveryCandidate, 0, len(byHost))
	for _, c := range byHost {
		if aid, ok := imported[DiscoveryCandidateDedupKey(c.Address)]; ok {
			c.Status = model.AssetDiscoveryCandidateImported
			c.ImportedID = aid
			continue
		}
		c.ID = qulid.GenerateID()
		rows = append(rows, *c)
	}
	ApplyLibraryMatchToDiscoveryCandidates(db, rows)
	if len(rows) > 0 {
		if err := tx.CreateInBatches(rows, 200).Error; err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit().Error; err != nil {
		return 0, err
	}
	DedupeDiscoveryCandidatesByProbe(db, probeID)

	if err := refreshProbeCandidateCounts(db, probeID); err != nil {
		return len(rows), err
	}
	slog.Info("[AssetDiscovery] 候选已同步", "probe_id", probeID, "task_ids", taskIDs, "candidates", len(rows))
	return len(rows), nil
}

// RefreshProbeCandidateCounts 刷新探测任务的候选统计。
func RefreshProbeCandidateCounts(db *gorm.DB, probeID string) error {
	return refreshProbeCandidateCounts(db, probeID)
}

func refreshProbeCandidateCounts(db *gorm.DB, probeID string) error {
	var total, pending, verified, imported int64
	base := db.Model(&model.AssetDiscoveryCandidate{}).Where("probe_id = ?", probeID)
	_ = base.Count(&total).Error
	_ = db.Model(&model.AssetDiscoveryCandidate{}).Where("probe_id = ? AND status = ?", probeID, model.AssetDiscoveryCandidatePending).Count(&pending).Error
	_ = db.Model(&model.AssetDiscoveryCandidate{}).Where("probe_id = ? AND status = ?", probeID, model.AssetDiscoveryCandidateVerified).Count(&verified).Error
	_ = db.Model(&model.AssetDiscoveryCandidate{}).Where("probe_id = ? AND status = ?", probeID, model.AssetDiscoveryCandidateImported).Count(&imported).Error
	return db.Model(&model.AssetDiscoveryProbe{}).Where("id = ?", probeID).Updates(map[string]interface{}{
		"candidate_total": int(total),
		"pending_count":   int(pending),
		"verified_count":  int(verified),
		"imported_count":  int(imported),
	}).Error
}

func discoveryHostFromFinding(f *model.ScanFinding) string {
	if f == nil {
		return ""
	}
	if f.Target != "" {
		host := strings.TrimSpace(f.Target)
		if idx := strings.Index(host, "://"); idx >= 0 {
			host = host[idx+3:]
		}
		if i := strings.LastIndex(host, ":"); i > 0 && strings.Contains(host, ".") {
			if p, err := strconv.Atoi(host[i+1:]); err == nil && p > 0 && p < 65536 {
				host = host[:i]
			}
		}
		host = strings.Trim(host, "/")
		if host != "" {
			return host
		}
	}
	if ip := discoveryDataStr(f.Data, "ip"); ip != "" {
		return ip
	}
	return ""
}

func discoveryAssetType(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return "host"
	}
	if strings.Contains(host, ".") {
		return "domain"
	}
	return "host"
}

// DedupeDiscoveryCandidatesByProbe 清理同探测下地址重复的历史候选（保留 updated_at 最新一条）。
func DedupeDiscoveryCandidatesByProbe(db *gorm.DB, probeID string) {
	if db == nil || probeID == "" {
		return
	}
	var rows []model.AssetDiscoveryCandidate
	if err := db.Where("probe_id = ?", probeID).Order("updated_at DESC").Find(&rows).Error; err != nil {
		return
	}
	seen := map[string]string{}
	var remove []string
	for i := range rows {
		key := DiscoveryCandidateDedupKey(rows[i].Address)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			remove = append(remove, rows[i].ID)
			continue
		}
		seen[key] = rows[i].ID
	}
	if len(remove) > 0 {
		_ = db.Delete(&model.AssetDiscoveryCandidate{}, "id IN ?", remove).Error
	}
}

func discoveryDataStr(data model.JSONMap, key string) string {
	if data == nil {
		return ""
	}
	v, ok := data[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func discoveryDataInt(data model.JSONMap, key string) int {
	s := discoveryDataStr(data, key)
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func discoveryProbeIDFromTaskParams(params model.JSONMap) string {
	if params == nil {
		return ""
	}
	v, ok := params["asset_discovery_probe_id"]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func discoveryEvidence(f *model.ScanFinding) string {
	if f == nil {
		return ""
	}
	if f.Evidence != "" {
		return f.Evidence
	}
	return f.Description
}

func UpdateProbeStatusFromTask(db *gorm.DB, probe *model.AssetDiscoveryProbe, task *model.ScanTask) error {
	if db == nil || probe == nil || task == nil {
		return nil
	}
	updates := map[string]interface{}{
		"task_id": task.ID,
	}
	switch task.Status {
	case model.TaskStatusRunning, model.TaskStatusQueued, model.TaskStatusSplitting:
		updates["status"] = model.AssetDiscoveryProbeRunning
		if task.StartedAt != nil {
			updates["started_at"] = task.StartedAt
		}
	case model.TaskStatusCompleted, model.TaskStatusPartial:
		updates["status"] = model.AssetDiscoveryProbeCompleted
		updates["finished_at"] = time.Now()
		if task.FinishedAt != nil {
			updates["finished_at"] = task.FinishedAt
		}
		taskIDs := discoveryScanTaskIDs(db, task.ID)
		if _, err := SyncAssetDiscoveryCandidates(db, probe.ID, taskIDs); err != nil {
			return err
		}
		_ = refreshProbeCandidateCounts(db, probe.ID)
	case model.TaskStatusFailed:
		updates["status"] = model.AssetDiscoveryProbeFailed
		updates["error_msg"] = task.ErrorMsg
		updates["finished_at"] = time.Now()
	case model.TaskStatusCancelled:
		updates["status"] = model.AssetDiscoveryProbeCancelled
		updates["finished_at"] = time.Now()
	}
	return db.Model(probe).Updates(updates).Error
}
