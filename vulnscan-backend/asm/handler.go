package asm

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc           *ServiceASM
	engine        *ConcurrentDiscoveryEngine
	diff          *DiffEngine
	alert         *AlertEngine
	allCollectors []AssetCollector
	mu            sync.Mutex
}

func NewHandler(svc *ServiceASM, extraCollectors ...AssetCollector) *Handler {
	sess := svc.session()
	return &Handler{
		svc:           svc,
		engine:        NewConcurrentDiscoveryEngine(10, 120*time.Second, extraCollectors...),
		diff:          NewDiffEngine(),
		alert:         NewAlertEngine(sess),
		allCollectors: extraCollectors,
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

	h.svc.UpdateProject(projectID, map[string]interface{}{
		"discovery_status": "running",
	})

	go h.executeDiscovery(project, dbSeeds)

	web.OK(c).Data(gin.H{"status": "running", "project_id": projectID}).Send()
}

func (h *Handler) executeDiscovery(project *model.ASMProject, dbSeeds []model.ASMSeed) {
	projectID := project.ID

	asmProject := &ASMProject{
		ID:   project.ID,
		Name: project.Name,
	}
	for _, s := range dbSeeds {
		asmProject.Seeds = append(asmProject.Seeds, Seed{Type: s.Type, Value: s.Value})
	}

	prevAssets := h.svc.GetPreviousAssets(projectID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	engine := h.getEngineForProject(project)
	discovered, err := engine.Discover(ctx, asmProject)
	if err != nil {
		slog.Error("ASM发现引擎执行失败", "project", projectID, "error", err)
		h.svc.UpdateProject(projectID, map[string]interface{}{
			"discovery_status": "failed",
		})
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
	h.alert.EvaluateRules(projectID, changes, discovered)

	h.svc.UpdateProject(projectID, map[string]interface{}{
		"discovery_status":  "completed",
		"last_discovery_at": now,
	})

	slog.Info("ASM发现完成", "project", projectID, "assets", len(newAssets), "changes", len(changes))
}

func (h *Handler) getEngineForProject(project *model.ASMProject) *ConcurrentDiscoveryEngine {
	if project.CollectorConfig == nil {
		return h.engine
	}
	enabledList, ok := project.CollectorConfig["enabled_collectors"]
	if !ok {
		return h.engine
	}
	names, ok := enabledList.([]interface{})
	if !ok || len(names) == 0 {
		return h.engine
	}
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		if s, ok := n.(string); ok {
			nameSet[s] = true
		}
	}
	var filtered []AssetCollector
	for _, c := range h.allCollectors {
		if nameSet[c.Name()] {
			filtered = append(filtered, c)
		}
	}
	if len(filtered) == 0 {
		return h.engine
	}
	return NewConcurrentDiscoveryEngine(10, 10*time.Minute, filtered...)
}

func (h *Handler) DiscoveryStatus(c *gin.Context) {
	projectID := c.Param("id")
	project, _, err := h.svc.GetProject(projectID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(gin.H{
		"status":            project.DiscoveryStatus,
		"last_discovery_at": project.LastDiscoveryAt,
	}).Send()
}

func (h *Handler) ListDiscoveredAssets(c *gin.Context) {
	projectID := c.Param("id")
	query, ok := web.BindQuery[AssetListQuery](c)
	if !ok {
		return
	}
	assets, count := h.svc.ListDiscoveredAssets(projectID, query)
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

func (h *Handler) ExportAssets(c *gin.Context) {
	projectID := c.Param("id")
	assets, _ := h.svc.GetAllAssets(projectID)

	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=asm_assets.csv")

	c.Writer.WriteString("\xEF\xBB\xBF")
	c.Writer.WriteString("类型,值,来源,风险分,状态,首次发现,最后发现\n")
	for _, a := range assets {
		line := fmt.Sprintf("%s,%s,%s,%d,%s,%s,%s\n",
			a.Type, csvEscape(a.Value), csvEscape(a.Source),
			a.RiskScore, a.Status,
			a.FirstSeen.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339))
		c.Writer.WriteString(line)
	}
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
