package aifingerprint

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler AI 指纹 HTTP 接口。
type Handler struct {
	svc *EnhancedService
}

// NewHandler 创建 Handler。
func NewHandler(svc *EnhancedService) *Handler {
	return &Handler{svc: svc}
}

// AnalyzeFingerprintRequest 指纹分析请求。
type AnalyzeFingerprintRequest struct {
	// RawData 键值对形式的原始数据：
	//   "banner" -> banner 文本
	//   "http_headers" -> HTTP 响应头
	//   "html" -> 网页 HTML 片段
	//   "ssl_cert" -> SSL 证书信息
	RawData map[string]string `json:"raw_data" binding:"required"`
}

// AnalyzeFingerprint 分析指纹 API。
func (h *Handler) AnalyzeFingerprint(c *gin.Context) {
	var req AnalyzeFingerprintRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results, err := h.svc.AnalyzeFingerprintRAG(c.Request.Context(), req.RawData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": results})
}

// AnalyzeRelationsRequest 关联分析请求。
type AnalyzeRelationsRequest struct {
	Entities []EntityInfo `json:"entities" binding:"required,min=2"`
}

// AnalyzeRelations 跨实体关联分析 API。
func (h *Handler) AnalyzeRelations(c *gin.Context) {
	var req AnalyzeRelationsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results, err := h.svc.AnalyzeRelations(c.Request.Context(), req.Entities)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": results})
}

// KnowledgeStats 知识库统计信息。
func (h *Handler) KnowledgeStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"knowledge_entries": h.svc.KnowledgeCount(),
		},
	})
}

// LearnRequest 学习请求。
type LearnRequest struct {
	Result   FingerprintResult `json:"result" binding:"required"`
	Patterns []string          `json:"patterns"`
}

// Learn 将确认的指纹加入知识库。
func (h *Handler) Learn(c *gin.Context) {
	var req LearnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.svc.LearnFromResult(req.Result, req.Patterns)
	c.JSON(http.StatusOK, gin.H{"message": "learned"})
}
