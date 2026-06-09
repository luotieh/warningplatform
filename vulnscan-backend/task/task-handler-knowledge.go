package task

import (
	"strings"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type vulnKnowledgeQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	VulnType string `form:"vuln_type"`
}

func (h *HandlerTask) ListVulnKnowledge(c *gin.Context) {
	query, ok := web.BindQuery[vulnKnowledgeQuery](c)
	if !ok {
		return
	}
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 {
		query.PageSize = 20
	}

	sess := h.svc.DB()
	q := sess.Model(&model.VulnKnowledgeCache{})
	if kw := strings.TrimSpace(query.Keyword); kw != "" {
		like := "%" + kw + "%"
		q = q.Where("title LIKE ? OR cve_id LIKE ? OR description LIKE ?", like, like, like)
	}
	if vt := strings.TrimSpace(query.VulnType); vt != "" {
		q = q.Where("vuln_type = ?", vt)
	}

	var total int64
	q.Count(&total)

	var items []model.VulnKnowledgeCache
	q.Order("hit_count DESC, updated_at DESC").
		Offset((query.Page - 1) * query.PageSize).
		Limit(query.PageSize).
		Find(&items)

	web.Succeed(c).List(total, items).Send()
}

func (h *HandlerTask) UpdateVulnKnowledge(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Description string `json:"description"`
		Cause       string `json:"cause"`
		Remediation string `json:"remediation"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	sess := h.svc.DB()
	var item model.VulnKnowledgeCache
	if err := sess.Where("id = ?", id).First(&item).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	updates := map[string]any{}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Cause != "" {
		updates["cause"] = req.Cause
	}
	if req.Remediation != "" {
		updates["remediation"] = req.Remediation
	}
	if len(updates) > 0 {
		sess.Model(&item).Updates(updates)
	}
	web.Succeed(c).Data(item).Send()
}

func (h *HandlerTask) DeleteVulnKnowledge(c *gin.Context) {
	id := c.Param("id")
	sess := h.svc.DB()
	if err := sess.Where("id = ?", id).Delete(&model.VulnKnowledgeCache{}).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"deleted": id}).Send()
}
