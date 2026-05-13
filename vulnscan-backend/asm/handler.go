package asm

import (
	"context"
	"fmt"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc    *ServiceASM
	engine *ConcurrentDiscoveryEngine
	diff   *DiffEngine
	alert  *AlertEngine
}

func NewHandler(svc *ServiceASM, extraCollectors ...AssetCollector) *Handler {
	sess := svc.session()
	return &Handler{
		svc:    svc,
		engine: NewConcurrentDiscoveryEngine(10, 120*time.Second, extraCollectors...),
		diff:   NewDiffEngine(),
		alert:  NewAlertEngine(sess),
	}
}

func (h *Handler) ListProjects(c *gin.Context) {
	projects, count := h.svc.ListProjects()
	web.OK(c).List(count, projects).Send()
}

func (h *Handler) GetProject(c *gin.Context) {
	id := c.Param("id")
	project, seeds, err := h.svc.GetProject(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(gin.H{"project": project, "seeds": seeds}).Send()
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

	var seeds []model.ASMSeed
	for _, s := range req.Seeds {
		seeds = append(seeds, model.ASMSeed{
			ID:        fmt.Sprintf("asms_%d", time.Now().UnixNano()),
			ProjectID: project.ID,
			Type:      s.Type,
			Value:     s.Value,
			Enabled:   true,
		})
	}

	if err := h.svc.CreateProject(&project, seeds); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(project).Send()
}

func (h *Handler) UpdateProject(c *gin.Context) {
	id := c.Param("id")
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	if err := h.svc.UpdateProject(id, body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) DeleteProject(c *gin.Context) {
	id := c.Param("id")
	h.svc.DeleteProject(id)
	web.OK(c).Send()
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
	if err := h.svc.AddSeed(&seed); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(seed).Send()
}

func (h *Handler) DeleteSeed(c *gin.Context) {
	seedID := c.Param("seed_id")
	h.svc.DeleteSeed(seedID)
	web.OK(c).Send()
}

func (h *Handler) RunDiscovery(c *gin.Context) {
	projectID := c.Param("id")

	project, dbSeeds, err := h.svc.GetProjectWithSeeds(projectID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	asmProject := &ASMProject{
		ID:   project.ID,
		Name: project.Name,
	}
	for _, s := range dbSeeds {
		asmProject.Seeds = append(asmProject.Seeds, Seed{Type: s.Type, Value: s.Value})
	}

	prevAssets := h.svc.GetPreviousAssets(projectID)

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

	h.svc.SaveDiscoveryResults(projectID, newAssets, dbChanges)

	alerts := h.alert.EvaluateRules(projectID, changes, discovered)

	web.OK(c).Data(gin.H{
		"discovered": len(newAssets),
		"changes":    len(changes),
		"alerts":     alerts,
	}).Send()
}

func (h *Handler) ListDiscoveredAssets(c *gin.Context) {
	projectID := c.Param("id")
	assets, count := h.svc.ListDiscoveredAssets(projectID)
	web.OK(c).List(count, assets).Send()
}

func (h *Handler) ListChanges(c *gin.Context) {
	projectID := c.Param("id")
	changes, count := h.svc.ListChanges(projectID)
	web.OK(c).List(count, changes).Send()
}

func (h *Handler) ListAlertRules(c *gin.Context) {
	projectID := c.Param("id")
	rules := h.svc.ListAlertRules(projectID)
	web.OK(c).Data(rules).Send()
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
	if err := h.svc.CreateAlertRule(&rule); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(rule).Send()
}

func (h *Handler) DeleteAlertRule(c *gin.Context) {
	ruleID := c.Param("rule_id")
	h.svc.DeleteAlertRule(ruleID)
	web.OK(c).Send()
}

func (h *Handler) ExposureReport(c *gin.Context) {
	projectID := c.Param("id")
	report := h.svc.ExposureReport(projectID)
	web.OK(c).Data(gin.H{
		"total_assets":      report.TotalAssets,
		"type_distribution": report.TypeDistribution,
		"source_stats":      report.SourceStats,
		"risk_distribution": report.RiskDistribution,
		"recent_changes":    report.RecentChanges,
		"open_alerts":       report.OpenAlerts,
		"top_risk_assets":   report.TopRiskAssets,
	}).Send()
}
