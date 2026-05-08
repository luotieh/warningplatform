package intel

import (
	"strings"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

func (h *Handler) ListCPEMappings(c *gin.Context) {
	keyword := strings.ToLower(c.Query("q"))

	mappings := h.matcher.GetCPEMappings()
	if keyword == "" {
		web.OK(c).Data(gin.H{"total": len(mappings), "mappings": mappings}).Send()
		return
	}

	var filtered []FingerprintCPEMapping
	for _, m := range mappings {
		if strings.Contains(strings.ToLower(m.Product), keyword) {
			filtered = append(filtered, m)
		}
	}
	web.OK(c).Data(gin.H{"total": len(filtered), "mappings": filtered}).Send()
}

func (h *Handler) AddCPEMapping(c *gin.Context) {
	var req struct {
		Product    string   `json:"product" binding:"required"`
		Version    string   `json:"version"`
		CPEMatches []string `json:"cpe_matches" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if req.Version == "" {
		req.Version = "*"
	}

	mapping := FingerprintCPEMapping{
		Product:    req.Product,
		Version:    req.Version,
		CPEMatches: req.CPEMatches,
	}
	h.matcher.AddCPEMapping(mapping)
	web.RespContent(c, web.Success, mapping)
}

func (h *Handler) UpdateCPEMapping(c *gin.Context) {
	product := c.Param("product")

	var req struct {
		Version    *string  `json:"version"`
		CPEMatches []string `json:"cpe_matches"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	updated := h.matcher.UpdateCPEMapping(product, func(m *FingerprintCPEMapping) {
		if req.Version != nil {
			m.Version = *req.Version
		}
		if req.CPEMatches != nil {
			m.CPEMatches = req.CPEMatches
		}
	})

	if !updated {
		web.Resp(c, web.NotFound)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) DeleteCPEMapping(c *gin.Context) {
	product := c.Param("product")
	if !h.matcher.DeleteCPEMapping(product) {
		web.Resp(c, web.NotFound)
		return
	}
	web.Resp(c, web.Success)
}
