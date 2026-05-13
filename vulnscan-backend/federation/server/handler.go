package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	fedAuth "vulnscan-backend/federation/auth"
	fedSync "vulnscan-backend/federation/sync"
	"vulnscan-backend/model"
)

// Handler serves the Central Master federation API.
type Handler struct {
	db             *gorm.DB
	versionManager *fedSync.VersionManager
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		db:             db,
		versionManager: fedSync.NewVersionManager(db),
	}
}

// Register handles sub-master registration.
func (h *Handler) Register(c *gin.Context) {
	req, ok := web.BindJSON[fedSync.RegisterRequest](c)
	if !ok {
		return
	}

	if req.SubMasterCode == "" || req.LicenseKey == "" {
		web.Fail(c).Msg("sub_master_code and license_key are required").Send()
		return
	}

	var license model.FederationLicense
	if err := h.db.Where("license_key = ? AND status = ?", req.LicenseKey, model.LicenseActive).First(&license).Error; err != nil {
		web.R(c).Code(web.Failed).HTTP(http.StatusForbidden).Msg("invalid or expired license").Send()
		return
	}

	if license.ExpiresAt.Before(time.Now()) {
		web.R(c).Code(web.Failed).HTTP(http.StatusForbidden).Msg("license expired").Send()
		return
	}

	apiToken := fedAuth.GenerateAPIToken(req.SubMasterCode)

	sm := model.SubMaster{
		ID:               qulid.GenerateID(),
		TenantID:         license.TenantID,
		SubMasterCode:    req.SubMasterCode,
		Hostname:         req.Hostname,
		IPAddress:        req.IPAddress,
		Version:          req.Version,
		Status:           model.SubMasterOnline,
		LicenseID:        license.ID,
		LicenseExpiresAt: &license.ExpiresAt,
		Capabilities:     req.Capabilities,
		APIToken:         apiToken,
		LastHeartbeatAt:  timePtr(time.Now()),
	}

	result := h.db.Where("sub_master_code = ?", req.SubMasterCode).
		Assign(model.SubMaster{
			Hostname:         req.Hostname,
			IPAddress:        req.IPAddress,
			Version:          req.Version,
			Status:           model.SubMasterOnline,
			LicenseID:        license.ID,
			LicenseExpiresAt: &license.ExpiresAt,
			Capabilities:     req.Capabilities,
			APIToken:         apiToken,
			LastHeartbeatAt:  timePtr(time.Now()),
		}).
		FirstOrCreate(&sm)

	if result.Error != nil {
		slog.Error("[Federation] 注册分主控失败", "error", result.Error)
		web.Fail(c).Msg("registration failed").Err(result.Error).Send()
		return
	}

	slog.Info("[Federation] 分主控注册成功", "code", req.SubMasterCode, "ip", req.IPAddress)

	web.OK(c).Data(fedSync.RegisterResponse{
		APIToken:       apiToken,
		SyncInterval:   "10m",
		ReportInterval: "5m",
		Quota: fedSync.QuotaInfo{
			MaxWorkers:  license.MaxWorkers,
			MaxTargets:  license.MaxTargets,
			MaxScansDay: license.MaxScansDay,
			Modules:     license.Modules,
			Features:    license.Features,
		},
		CurrentVersions: h.versionManager.AllVersions(),
	}).Send()
}

// Heartbeat handles sub-master heartbeats.
func (h *Handler) Heartbeat(c *gin.Context) {
	req, ok := web.BindJSON[fedSync.HeartbeatRequest](c)
	if !ok {
		return
	}

	subCode := c.GetString("sub_master_code")
	if subCode == "" {
		subCode = req.SubMasterCode
	}

	now := time.Now()
	updates := map[string]interface{}{
		"status":              model.SubMasterOnline,
		"last_heartbeat_at":   now,
		"cpu_percent":         req.CPUPercent,
		"mem_percent":         req.MemPercent,
		"worker_count":        req.WorkerCount,
		"active_tasks":        req.ActiveTasks,
		"current_targets":     req.CurrentTargets,
		"scans_today":         req.ScansToday,
		"poc_version":         req.PocVersion,
		"fingerprint_version": req.FPVersion,
		"rule_version":        req.RuleVersion,
		"updated_at":          now,
	}

	h.db.Model(&model.SubMaster{}).Where("sub_master_code = ?", subCode).Updates(updates)

	web.OK(c).Data(fedSync.HeartbeatResponse{
		Status:          "ok",
		CurrentVersions: h.versionManager.AllVersions(),
	}).Send()
}

// SyncPoc serves incremental PoC sync.
func (h *Handler) SyncPoc(c *gin.Context) {
	h.handleSync(c, model.SyncDataTypePoc)
}

// SyncFingerprint serves incremental fingerprint sync.
func (h *Handler) SyncFingerprint(c *gin.Context) {
	h.handleSync(c, model.SyncDataTypeFingerprint)
}

// SyncRule serves incremental rule sync.
func (h *Handler) SyncRule(c *gin.Context) {
	h.handleSync(c, model.SyncDataTypeRule)
}

func (h *Handler) handleSync(c *gin.Context, dataType string) {
	sinceVersion, _ := strconv.ParseInt(c.Query("since_version"), 10, 64)
	limit, _ := strconv.Atoi(c.Query("limit"))
	if limit <= 0 {
		limit = 500
	}

	subCode := c.GetString("sub_master_code")
	start := time.Now()

	var resp *fedSync.SyncResponse
	var err error

	switch dataType {
	case model.SyncDataTypePoc:
		resp, err = h.versionManager.GetPocDelta(sinceVersion, limit)
	case model.SyncDataTypeFingerprint:
		resp, err = h.versionManager.GetFingerprintDelta(sinceVersion, limit)
	case model.SyncDataTypeRule:
		resp, err = h.versionManager.GetRuleDelta(sinceVersion, limit)
	default:
		web.Fail(c).Msg("unknown data type").Send()
		return
	}

	durMs := int(time.Since(start).Milliseconds())

	if err != nil {
		h.versionManager.LogSync(subCode, dataType, sinceVersion, 0, 0, "failed", err.Error(), durMs)
		web.Fail(c).Msg("sync failed").Err(err).Send()
		return
	}

	var toVer int64
	if len(resp.Items) > 0 {
		toVer = resp.Items[len(resp.Items)-1].SyncVersion
	}
	h.versionManager.LogSync(subCode, dataType, sinceVersion, toVer, len(resp.Items), "success", "", durMs)

	web.OK(c).Data(resp).Send()
}

// SyncManifest returns current version numbers for all data types.
func (h *Handler) SyncManifest(c *gin.Context) {
	web.OK(c).Data(fedSync.ManifestResponse{
		Versions:   h.versionManager.AllVersions(),
		ServerTime: time.Now(),
	}).Send()
}

// vulnReportPayload is the request body for ReceiveVulnReport.
type vulnReportPayload struct {
	ReportAt   time.Time        `json:"report_at"`
	Period     string           `json:"period"`
	TotalVulns int64            `json:"total_vulns"`
	BySeverity map[string]int64 `json:"by_severity"`
	ByType     map[string]int64 `json:"by_type"`
	NewVulns   int64            `json:"new_vulns"`
	FixedVulns int64            `json:"fixed_vulns"`
}

// scanReportPayload is the request body for ReceiveScanReport.
type scanReportPayload struct {
	ReportAt       time.Time `json:"report_at"`
	ActiveTasks    int64     `json:"active_tasks"`
	CompletedToday int64     `json:"completed_today"`
	TotalTargets   int64     `json:"total_targets"`
	ActiveWorkers  int64     `json:"active_workers"`
	AvgScanTime    float64   `json:"avg_scan_time_sec"`
}

// ReceiveVulnReport accepts vulnerability summary reports from sub-masters.
func (h *Handler) ReceiveVulnReport(c *gin.Context) {
	subCode := c.GetString("sub_master_code")

	payload, ok := web.BindJSON[vulnReportPayload](c)
	if !ok {
		return
	}

	var sm model.SubMaster
	h.db.Where("sub_master_code = ?", subCode).First(&sm)

	rec := model.AggregateVuln{
		ID:          qulid.GenerateID(),
		SubMasterID: subCode,
		TenantID:    sm.TenantID,
		ReportAt:    payload.ReportAt,
		Period:      payload.Period,
		TotalVulns:  payload.TotalVulns,
		BySeverity:  toJSONMap(payload.BySeverity),
		ByType:      toJSONMap(payload.ByType),
		NewVulns:    payload.NewVulns,
		FixedVulns:  payload.FixedVulns,
		CreatedAt:   time.Now(),
	}

	if err := h.db.Create(&rec).Error; err != nil {
		web.Fail(c).Msg("store report failed").Err(err).Send()
		return
	}

	web.OK(c).Data(gin.H{"status": "received"}).Send()
}

// ReceiveScanReport accepts scan statistics from sub-masters.
func (h *Handler) ReceiveScanReport(c *gin.Context) {
	subCode := c.GetString("sub_master_code")

	payload, ok := web.BindJSON[scanReportPayload](c)
	if !ok {
		return
	}

	var sm model.SubMaster
	h.db.Where("sub_master_code = ?", subCode).First(&sm)

	rec := model.AggregateScan{
		ID:             qulid.GenerateID(),
		SubMasterID:    subCode,
		TenantID:       sm.TenantID,
		ReportAt:       payload.ReportAt,
		ActiveTasks:    payload.ActiveTasks,
		CompletedToday: payload.CompletedToday,
		TotalTargets:   payload.TotalTargets,
		ActiveWorkers:  payload.ActiveWorkers,
		AvgScanTime:    payload.AvgScanTime,
		CreatedAt:      time.Now(),
	}

	if err := h.db.Create(&rec).Error; err != nil {
		web.Fail(c).Msg("store report failed").Err(err).Send()
		return
	}

	web.OK(c).Data(gin.H{"status": "received"}).Send()
}

// ListSubMasters returns all registered sub-masters for the dashboard.
func (h *Handler) ListSubMasters(c *gin.Context) {
	var subs []model.SubMaster
	h.db.Order("updated_at DESC").Find(&subs)
	web.OK(c).List(int64(len(subs)), subs).Send()
}

// GlobalStats provides aggregated stats for the federation dashboard.
func (h *Handler) GlobalStats(c *gin.Context) {
	var totalSubs int64
	var onlineSubs int64
	h.db.Model(&model.SubMaster{}).Count(&totalSubs)
	h.db.Model(&model.SubMaster{}).Where("status = ?", model.SubMasterOnline).Count(&onlineSubs)

	versions := h.versionManager.AllVersions()

	web.OK(c).Data(gin.H{
		"total_sub_masters":  totalSubs,
		"online_sub_masters": onlineSubs,
		"current_versions":   versions,
	}).Send()
}

func timePtr(t time.Time) *time.Time { return &t }

func toJSONMap(m map[string]int64) model.JSONMap {
	if m == nil {
		return nil
	}
	out := make(model.JSONMap, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
