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
	req, ok := web.BindJSON[AddCPEMappingReq](c)
	if !ok {
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
	web.OK(c).Data(mapping).Send()
}

func (h *Handler) UpdateCPEMapping(c *gin.Context) {
	product := c.Param("product")

	req, ok := web.BindJSON[UpdateCPEMappingReq](c)
	if !ok {
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
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) DeleteCPEMapping(c *gin.Context) {
	product := c.Param("product")
	if !h.matcher.DeleteCPEMapping(product) {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Send()
}
