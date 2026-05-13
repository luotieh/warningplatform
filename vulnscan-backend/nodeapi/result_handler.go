package nodeapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type DBMonitorResultHandler struct {
	db *gorm.DB
}

func NewDBMonitorResultHandler(db *gorm.DB) *DBMonitorResultHandler {
	return &DBMonitorResultHandler{db: db}
}

func (h *DBMonitorResultHandler) HandleMonitorResult(executionID, status, errMsg, result, startedAt, finishedAt string) {
	updates := map[string]any{
		"status":      status,
		"result_json": result,
	}
	if errMsg != "" {
		updates["error"] = errMsg
	}
	if startedAt != "" {
		if t, err := time.Parse(time.RFC3339, startedAt); err == nil {
			updates["started_at"] = t
		}
	}
	if finishedAt != "" {
		if t, err := time.Parse(time.RFC3339, finishedAt); err == nil {
			updates["finished_at"] = t
		}
	}

	if err := h.db.Model(&model.MonitorExecution{}).
		Where("id = ?", executionID).
		Updates(updates).Error; err != nil {
		slog.Error("save monitor result failed", "execution_id", executionID, "error", err)
	}
}

type DBScanResultHandler struct {
	db *gorm.DB
}

func NewDBScanResultHandler(db *gorm.DB) *DBScanResultHandler {
	return &DBScanResultHandler{db: db}
}

func (h *DBScanResultHandler) HandleScanResult(taskID, status, errMsg string, progress float64, resultJSON string, finishedAt *time.Time) {
	updates := map[string]any{
		"status":   status,
		"progress": progress,
	}
	if errMsg != "" {
		updates["error_msg"] = errMsg
	}
	if finishedAt != nil {
		updates["finished_at"] = finishedAt
	}

	if err := h.db.Model(&model.ScanTask{}).
		Where("id = ?", taskID).
		Updates(updates).Error; err != nil {
		slog.Error("save scan result failed", "task_id", taskID, "error", err)
		return
	}

	if resultJSON == "" {
		return
	}

	var scanResult struct {
		Vulnerabilities []model.Vulnerability `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &scanResult); err != nil {
		return
	}

	if len(scanResult.Vulnerabilities) > 0 {
		h.saveVulnerabilities(taskID, scanResult.Vulnerabilities)
	}
}

func (h *DBScanResultHandler) saveVulnerabilities(taskID string, vulns []model.Vulnerability) {
	var assets []model.Asset
	h.db.Select("id, address, ipv4, domain, url, port").Find(&assets)
	assetIndex := buildAssetIndex(assets)

	for i := range vulns {
		vulns[i].TaskID = taskID
		if vulns[i].ID == "" {
			vulns[i].ID = fmt.Sprintf("vuln_%d_%d", time.Now().UnixNano(), i)
		}
		vulns[i].AssetID = matchAsset(assetIndex, vulns[i].Target, vulns[i].Port)
	}

	h.db.CreateInBatches(vulns, 100)
	slog.Info("vulnerabilities saved", "task_id", taskID, "count", len(vulns))
}

type assetIndexEntry struct {
	ID   string
	Port int
}

func buildAssetIndex(assets []model.Asset) map[string][]assetIndexEntry {
	idx := make(map[string][]assetIndexEntry, len(assets)*3)
	for _, a := range assets {
		entry := assetIndexEntry{ID: a.ID, Port: a.Port}
		if a.Address != "" {
			idx[a.Address] = append(idx[a.Address], entry)
		}
		if a.IPv4 != "" && a.IPv4 != a.Address {
			idx[a.IPv4] = append(idx[a.IPv4], entry)
		}
		if a.Domain != "" {
			idx[a.Domain] = append(idx[a.Domain], entry)
		}
		if a.URL != "" {
			idx[a.URL] = append(idx[a.URL], entry)
		}
	}
	return idx
}

func matchAsset(idx map[string][]assetIndexEntry, target string, port int) string {
	if entries, ok := idx[target]; ok {
		for _, e := range entries {
			if port == 0 || e.Port == 0 || e.Port == port {
				return e.ID
			}
		}
		return entries[0].ID
	}
	return ""
}
