package server

import (
	"time"

	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	fedSync "vulnscan-backend/federation/sync"
	"vulnscan-backend/model"
)

type ManageAPI struct {
	db             *gorm.DB
	versionManager *fedSync.VersionManager
}

func RegisterManageRoutes(g *gin.RouterGroup, db *gorm.DB) []authorize.BackendItem {
	api := &ManageAPI{
		db:             db,
		versionManager: fedSync.NewVersionManager(db),
	}
	return authorize.RegisterRoutes(g.Group("/federation"), []authorize.Route{
		{Name: "子节点列表", Path: "sub-masters", Method: "GET", Handler: api.ListSubMasters, Enabled: true},
		{Name: "联邦统计", Path: "stats", Method: "GET", Handler: api.Stats, Enabled: true},
	})
}

type subMasterItem struct {
	ID              string     `json:"id"`
	SubMasterCode   string     `json:"sub_master_code"`
	Hostname        string     `json:"hostname"`
	IPAddress       string     `json:"ip_address"`
	Version         string     `json:"version"`
	Status          string     `json:"status"`
	CPUPercent      float64    `json:"cpu_percent"`
	MemPercent      float64    `json:"mem_percent"`
	WorkerCount     int        `json:"worker_count"`
	ActiveTasks     int        `json:"active_tasks"`
	ScansToday      int        `json:"scans_today"`
	PocVersion      int64      `json:"poc_version"`
	FPVersion       int64      `json:"fingerprint_version"`
	RuleVersion     int64      `json:"rule_version"`
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at"`
}

func (a *ManageAPI) ListSubMasters(c *gin.Context) {
	var subs []model.SubMaster
	a.db.Order("updated_at DESC").Find(&subs)

	items := make([]subMasterItem, 0, len(subs))
	for _, s := range subs {
		items = append(items, subMasterItem{
			ID:              s.ID,
			SubMasterCode:   s.SubMasterCode,
			Hostname:        s.Hostname,
			IPAddress:       s.IPAddress,
			Version:         s.Version,
			Status:          s.Status,
			CPUPercent:      s.CPUPercent,
			MemPercent:      s.MemPercent,
			WorkerCount:     s.WorkerCount,
			ActiveTasks:     s.ActiveTasks,
			ScansToday:      s.ScansToday,
			PocVersion:      s.PocVersion,
			FPVersion:       s.FingerprintVersion,
			RuleVersion:     s.RuleVersion,
			LastHeartbeatAt: s.LastHeartbeatAt,
		})
	}

	web.OK(c).List(int64(len(items)), items).Send()
}

func (a *ManageAPI) Stats(c *gin.Context) {
	var totalSubs int64
	var onlineSubs int64
	a.db.Model(&model.SubMaster{}).Count(&totalSubs)
	a.db.Model(&model.SubMaster{}).Where("status = ?", model.SubMasterOnline).Count(&onlineSubs)

	versions := a.versionManager.AllVersionsFromDB()

	web.OK(c).Data(gin.H{
		"total_sub_masters":  totalSubs,
		"online_sub_masters": onlineSubs,
		"current_versions":   versions,
	}).Send()
}
