package server

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	fedAuth "vulnscan-backend/federation/auth"
)

// RegisterRoutes mounts Federation API endpoints under /federation/v1/
func RegisterRoutes(engine *gin.Engine, db *gorm.DB) *Handler {
	h := NewHandler(db)

	fg := engine.Group("/federation/v1", fedAuth.FederationAuthMiddleware())
	{
		fg.POST("/register", h.Register)
		fg.POST("/heartbeat", h.Heartbeat)

		fg.GET("/sync/poc", h.SyncPoc)
		fg.GET("/sync/fingerprint", h.SyncFingerprint)
		fg.GET("/sync/rule", h.SyncRule)
		fg.GET("/sync/manifest", h.SyncManifest)

		fg.POST("/report/vuln", h.ReceiveVulnReport)
		fg.POST("/report/scan", h.ReceiveScanReport)

		fg.GET("/sub-masters", h.ListSubMasters)
		fg.GET("/stats", h.GlobalStats)
	}

	return h
}
