package aihub

import (
	"net/http"

	"vulnscan-backend/knowledge/aicompliance"
	"vulnscan-backend/knowledge/aicrawl"
	"vulnscan-backend/knowledge/aifingerprint"
	"vulnscan-backend/knowledge/aipayload"
	"vulnscan-backend/knowledge/aipoc"
	"vulnscan-backend/knowledge/aireport"
	"vulnscan-backend/knowledge/aistrategy"
	"vulnscan-backend/knowledge/aiverify"

	"github.com/gin-gonic/gin"
)

// Handler AI Hub HTTP 接口。
type Handler struct {
	hub *Hub
}

// NewHandler 创建 Handler。
func NewHandler(hub *Hub) *Handler {
	return &Handler{hub: hub}
}

// --- Fingerprint ---

func (h *Handler) AnalyzeFingerprint(c *gin.Context) {
	var req struct {
		RawData map[string]string `json:"raw_data" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	results, err := h.hub.Fingerprint.AnalyzeFingerprintRAG(c.Request.Context(), req.RawData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": results})
}

func (h *Handler) AnalyzeRelations(c *gin.Context) {
	var req struct {
		Entities []aifingerprint.EntityInfo `json:"entities" binding:"required,min=2"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	results, err := h.hub.Fingerprint.AnalyzeRelations(c.Request.Context(), req.Entities)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": results})
}

// --- Verify ---

func (h *Handler) VerifyVuln(c *gin.Context) {
	var req aiverify.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Verify.Verify(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// --- Payload ---

func (h *Handler) GeneratePayload(c *gin.Context) {
	var req aipayload.GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Payload.Generate(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// --- Crawl ---

func (h *Handler) AnalyzeForm(c *gin.Context) {
	var req aicrawl.FormAnalysisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Crawl.AnalyzeForm(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

func (h *Handler) PlanInteraction(c *gin.Context) {
	var req aicrawl.InteractionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Crawl.PlanInteraction(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// --- Report ---

func (h *Handler) GenerateReport(c *gin.Context) {
	var req aireport.VulnContext
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Report.GenerateVulnReport(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

func (h *Handler) GenerateExecutiveSummary(c *gin.Context) {
	var req aireport.BatchReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Report.GenerateExecutiveSummary(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// --- Strategy ---

func (h *Handler) RecommendStrategy(c *gin.Context) {
	var req aistrategy.TargetProfile
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Strategy.RecommendStrategy(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// --- Query ---

func (h *Handler) NLQuery(c *gin.Context) {
	var req struct {
		Question string `json:"question" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Query.ParseQuery(c.Request.Context(), req.Question)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// --- POC ---

func (h *Handler) GeneratePOC(c *gin.Context) {
	var req aipoc.GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.POC.Generate(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

func (h *Handler) ImprovePOC(c *gin.Context) {
	var req struct {
		ExistingPoc string `json:"existing_poc" binding:"required"`
		Feedback    string `json:"feedback" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.POC.Improve(c.Request.Context(), req.ExistingPoc, req.Feedback)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// --- Compliance ---

func (h *Handler) ComplianceAsk(c *gin.Context) {
	var req aicompliance.ComplianceQuery
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Compliance.Ask(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

func (h *Handler) ComplianceMapping(c *gin.Context) {
	var req aicompliance.VulnComplianceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.hub.Compliance.MapVulnToCompliance(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}
