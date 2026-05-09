package asm

import (
	"context"
	"fmt"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Handler struct {
	db     *db.DB
	engine *ConcurrentDiscoveryEngine
	diff   *DiffEngine
	alert  *AlertEngine
}

func NewHandler(database *db.DB, extraCollectors ...AssetCollector) *Handler {
	sess, _ := database.GetDBSession()
	return &Handler{
		db:     database,
		engine: NewConcurrentDiscoveryEngine(10, 120*time.Second, extraCollectors...),
		diff:   NewDiffEngine(),
		alert:  NewAlertEngine(sess),
	}
}

func (h *Handler) session() *gorm.DB {
	sess, _ := h.db.GetDBSession()
	return sess
}

func (h *Handler) ListProjects(c *gin.Context) {
	var projects []model.ASMProject
	var count int64
	q := h.session().Model(&model.ASMProject{})
	q.Count(&count)
	q.Order("created_at DESC").Find(&projects)
	web.RespContentWithNum(c, web.Success, count, projects)
}

func (h *Handler) GetProject(c *gin.Context) {
	id := c.Param("id")
	var project model.ASMProject
	if h.session().First(&project, "id = ?", id).Error != nil {
		web.Resp(c, web.NotFound)
		return
	}
	var seeds []model.ASMSeed
	h.session().Where("project_id = ?", id).Find(&seeds)
	web.RespContent(c, web.Success, gin.H{"project": project, "seeds": seeds})
}

func (h *Handler) CreateProject(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Schedule    string `json:"schedule"`
		Seeds       []struct {
			Type  string `json:"type" binding:"required"`
			Value string `json:"value" binding:"required"`
		} `json:"seeds"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	project := model.ASMProject{
		Name:        req.Name,
		Description: req.Description,
		Schedule:    req.Schedule,
		Enabled:     true,
	}
	project.ID = fmt.Sprintf("asmp_%d", time.Now().UnixNano())

	tx := h.session().Begin()
	if err := tx.Create(&project).Error; err != nil {
		tx.Rollback()
		web.Resp(c, web.InternalError)
		return
	}

	for _, s := range req.Seeds {
		seed := model.ASMSeed{
			ID:        fmt.Sprintf("asms_%d", time.Now().UnixNano()),
			ProjectID: project.ID,
			Type:      s.Type,
			Value:     s.Value,
			Enabled:   true,
		}
		if err := tx.Create(&seed).Error; err != nil {
			tx.Rollback()
			web.Resp(c, web.InternalError)
			return
		}
	}
	tx.Commit()

	web.RespContent(c, web.Success, project)
}

func (h *Handler) UpdateProject(c *gin.Context) {
	id := c.Param("id")
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if err := h.session().Model(&model.ASMProject{}).Where("id = ?", id).Updates(body).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) DeleteProject(c *gin.Context) {
	id := c.Param("id")
	tx := h.session().Begin()
	tx.Where("project_id = ?", id).Delete(&model.ASMSeed{})
	tx.Where("project_id = ?", id).Delete(&model.ASMDiscoveredAsset{})
	tx.Where("project_id = ?", id).Delete(&model.ASMChange{})
	tx.Where("id = ?", id).Delete(&model.ASMProject{})
	tx.Commit()
	web.Resp(c, web.Success)
}

func (h *Handler) AddSeed(c *gin.Context) {
	projectID := c.Param("id")
	var req struct {
		Type  string `json:"type" binding:"required"`
		Value string `json:"value" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	seed := model.ASMSeed{
		ID:        fmt.Sprintf("asms_%d", time.Now().UnixNano()),
		ProjectID: projectID,
		Type:      req.Type,
		Value:     req.Value,
		Enabled:   true,
	}
	if err := h.session().Create(&seed).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, seed)
}

func (h *Handler) DeleteSeed(c *gin.Context) {
	seedID := c.Param("seed_id")
	h.session().Where("id = ?", seedID).Delete(&model.ASMSeed{})
	web.Resp(c, web.Success)
}

func (h *Handler) RunDiscovery(c *gin.Context) {
	projectID := c.Param("id")

	var project model.ASMProject
	if h.session().First(&project, "id = ?", projectID).Error != nil {
		web.Resp(c, web.NotFound)
		return
	}

	var dbSeeds []model.ASMSeed
	h.session().Where("project_id = ? AND enabled = ?", projectID, true).Find(&dbSeeds)

	asmProject := &ASMProject{
		ID:   project.ID,
		Name: project.Name,
	}
	for _, s := range dbSeeds {
		asmProject.Seeds = append(asmProject.Seeds, Seed{Type: s.Type, Value: s.Value})
	}

	var prevAssets []model.ASMDiscoveredAsset
	h.session().Where("project_id = ?", projectID).Find(&prevAssets)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()

	discovered, err := h.engine.Discover(ctx, asmProject)
	if err != nil {
		web.Fail(c).Msg("发现引擎执行失败").Err(err).Send()
		return
	}

	now := time.Now()
	var newAssets []model.ASMDiscoveredAsset
	for _, d := range discovered {
		attrs := make(model.JSONMap, len(d.Attributes))
		for k, v := range d.Attributes {
			attrs[k] = v
		}
		newAssets = append(newAssets, model.ASMDiscoveredAsset{
			ID:         fmt.Sprintf("asmd_%d", time.Now().UnixNano()),
			ProjectID:  projectID,
			Type:       d.Type,
			Value:      d.Value,
			Source:     d.Source,
			Attributes: attrs,
			RiskScore:  d.RiskScore,
			Status:     d.Status,
			FirstSeen:  d.FirstSeen,
			LastSeen:   now,
		})
	}

	var prevDiscovered []DiscoveredAsset
	for _, pa := range prevAssets {
		prevDiscovered = append(prevDiscovered, DiscoveredAsset{
			ID:         pa.ID,
			ProjectID:  pa.ProjectID,
			Type:       pa.Type,
			Value:      pa.Value,
			Source:     pa.Source,
			Attributes: map[string]string{},
			Status:     pa.Status,
		})
	}

	changes := h.diff.Compare(prevDiscovered, discovered)

	tx := h.session().Begin()
	tx.Where("project_id = ?", projectID).Delete(&model.ASMDiscoveredAsset{})
	if len(newAssets) > 0 {
		tx.CreateInBatches(newAssets, 100)
	}
	if len(changes) > 0 {
		var dbChanges []model.ASMChange
		for _, ch := range changes {
			dbChanges = append(dbChanges, model.ASMChange{
				ID:        fmt.Sprintf("asmc_%d", time.Now().UnixNano()),
				ProjectID: projectID,
				AssetID:   ch.AssetID,
				Field:     ch.Field,
				OldValue:  ch.OldValue,
				NewValue:  ch.NewValue,
				Severity:  ch.Severity,
				ChangeAt:  ch.ChangeAt,
			})
		}
		tx.CreateInBatches(dbChanges, 100)
	}
	h.session().Model(&model.ASMSeed{}).Where("project_id = ?", projectID).Update("last_run_at", now)
	tx.Commit()

	alerts := h.alert.EvaluateRules(projectID, changes, discovered)

	web.OK(c).Data(gin.H{
		"discovered": len(newAssets),
		"changes":    len(changes),
		"alerts":     alerts,
	}).Send()
}

func (h *Handler) ListDiscoveredAssets(c *gin.Context) {
	projectID := c.Param("id")
	var assets []model.ASMDiscoveredAsset
	var count int64
	q := h.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ?", projectID)
	q.Count(&count)
	q.Order("risk_score DESC, last_seen DESC").Find(&assets)
	web.RespContentWithNum(c, web.Success, count, assets)
}

func (h *Handler) ListChanges(c *gin.Context) {
	projectID := c.Param("id")
	var changes []model.ASMChange
	var count int64
	q := h.session().Model(&model.ASMChange{}).Where("project_id = ?", projectID)
	q.Count(&count)
	q.Order("change_at DESC").Limit(200).Find(&changes)
	web.RespContentWithNum(c, web.Success, count, changes)
}

func (h *Handler) ListAlertRules(c *gin.Context) {
	projectID := c.Param("id")
	var rules []model.ASMAlertRule
	h.session().Where("project_id = ?", projectID).Order("created_at DESC").Find(&rules)
	web.RespContent(c, web.Success, rules)
}

func (h *Handler) CreateAlertRule(c *gin.Context) {
	projectID := c.Param("id")
	var req struct {
		Name      string        `json:"name" binding:"required"`
		Type      string        `json:"type" binding:"required"`
		Condition model.JSONMap `json:"condition"`
		Actions   model.JSONMap `json:"actions"`
		Enabled   bool          `json:"enabled"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	rule := model.ASMAlertRule{
		ID:        fmt.Sprintf("asmr_%d", time.Now().UnixNano()),
		ProjectID: projectID,
		Name:      req.Name,
		Type:      req.Type,
		Condition: req.Condition,
		Actions:   req.Actions,
		Enabled:   req.Enabled,
	}
	if err := h.session().Create(&rule).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, rule)
}

func (h *Handler) DeleteAlertRule(c *gin.Context) {
	ruleID := c.Param("rule_id")
	h.session().Where("id = ?", ruleID).Delete(&model.ASMAlertRule{})
	web.Resp(c, web.Success)
}

func (h *Handler) ExposureReport(c *gin.Context) {
	projectID := c.Param("id")

	type typeStat struct {
		Type  string `gorm:"column:type" json:"type"`
		Count int64  `gorm:"column:count" json:"count"`
	}
	var typeStats []typeStat
	h.session().Model(&model.ASMDiscoveredAsset{}).
		Where("project_id = ?", projectID).
		Select("type, COUNT(*) as count").
		Group("type").Find(&typeStats)

	type sourceStat struct {
		Source string `gorm:"column:source" json:"source"`
		Count  int64  `gorm:"column:count" json:"count"`
	}
	var sourceStats []sourceStat
	h.session().Model(&model.ASMDiscoveredAsset{}).
		Where("project_id = ?", projectID).
		Select("source, COUNT(*) as count").
		Group("source").Find(&sourceStats)

	type riskBucket struct {
		Bucket string `json:"bucket"`
		Count  int64  `json:"count"`
	}
	var total, highRisk, mediumRisk, lowRisk int64
	h.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ?", projectID).Count(&total)
	h.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ? AND risk_score >= 70", projectID).Count(&highRisk)
	h.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ? AND risk_score >= 40 AND risk_score < 70", projectID).Count(&mediumRisk)
	h.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ? AND risk_score < 40", projectID).Count(&lowRisk)

	riskDistribution := []riskBucket{
		{Bucket: "high (≥70)", Count: highRisk},
		{Bucket: "medium (40-69)", Count: mediumRisk},
		{Bucket: "low (<40)", Count: lowRisk},
	}

	var recentChanges int64
	h.session().Model(&model.ASMChange{}).Where("project_id = ?", projectID).Count(&recentChanges)

	var openAlerts int64
	h.session().Model(&model.Alert{}).Where("source = ? AND status = ?", "asm", "open").Count(&openAlerts)

	var topRiskAssets []model.ASMDiscoveredAsset
	h.session().Where("project_id = ?", projectID).Order("risk_score DESC").Limit(10).Find(&topRiskAssets)

	web.OK(c).Data(gin.H{
		"total_assets":      total,
		"type_distribution": typeStats,
		"source_stats":      sourceStats,
		"risk_distribution": riskDistribution,
		"recent_changes":    recentChanges,
		"open_alerts":       openAlerts,
		"top_risk_assets":   topRiskAssets,
	}).Send()
}
