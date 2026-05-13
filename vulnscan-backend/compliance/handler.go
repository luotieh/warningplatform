package compliance

import (
	"context"
	"time"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	engine     *CheckEngine
	frameworks map[string]*Framework
}

func NewHandler() *Handler {
	h := &Handler{
		engine:     NewCheckEngine(),
		frameworks: make(map[string]*Framework),
	}
	h.loadFrameworks()
	return h
}

func (h *Handler) loadFrameworks() {
	fws := []*Framework{
		CISLinuxLevel1(),
		DJCP2Level3(),
	}
	for _, fw := range fws {
		h.frameworks[fw.ID] = fw
	}
}

func (h *Handler) ListFrameworks(c *gin.Context) {
	var list []map[string]interface{}
	for _, fw := range h.frameworks {
		list = append(list, map[string]interface{}{
			"id":          fw.ID,
			"name":        fw.Name,
			"version":     fw.Version,
			"description": fw.Description,
			"standard":    fw.Standard,
			"rule_count":  len(fw.Rules),
		})
	}
	web.OK(c).Data(list).Send()
}

func (h *Handler) GetFramework(c *gin.Context) {
	id := c.Param("id")
	fw, ok := h.frameworks[id]
	if !ok {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(fw).Send()
}

func (h *Handler) RunCheck(c *gin.Context) {
	var req struct {
		FrameworkID string `json:"framework_id" binding:"required"`
		TargetIP    string `json:"target_ip" binding:"required"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		Port        int    `json:"port"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	fw, ok := h.frameworks[req.FrameworkID]
	if !ok {
		web.Fail(c).Msg("未找到基线框架: " + req.FrameworkID).Send()
		return
	}

	if req.Username != "" {
		creds := SSHCredentials{
			Username: req.Username,
			Password: req.Password,
			Port:     req.Port,
		}
		h.engine.collectors[CheckTypeCommand] = &CommandCollector{Creds: creds}
		h.engine.collectors[CheckTypeFile] = &FileCollector{Creds: creds}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()

	report := h.engine.RunFramework(ctx, fw, req.TargetIP)

	web.OK(c).Data(gin.H{
		"report":    report,
		"framework": fw.Name,
		"target":    req.TargetIP,
	}).Send()
}

func (h *Handler) GetRules(c *gin.Context) {
	id := c.Param("id")
	fw, ok := h.frameworks[id]
	if !ok {
		web.Err(c, web.NotFound).Send()
		return
	}

	category := c.Query("category")
	severity := c.Query("severity")

	var filtered []Rule
	for _, rule := range fw.Rules {
		if category != "" && rule.Category != category {
			continue
		}
		if severity != "" && rule.Severity != severity {
			continue
		}
		filtered = append(filtered, rule)
	}
	web.OK(c).Data(filtered).Send()
}
