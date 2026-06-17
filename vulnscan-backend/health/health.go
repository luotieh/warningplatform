package health

import (
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"time"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

var startTime = time.Now()

type Handler struct {
	db       *db.DB
	logLevel *slog.LevelVar
}

func NewHandler(db *db.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) SetLogLevel(lv *slog.LevelVar) {
	h.logLevel = lv
}

func (h *Handler) RegisterRoutes(engine *gin.Engine) {
	engine.GET("/health", h.Health)
	engine.GET("/health/ready", h.Ready)
	engine.GET("/health/system", h.System)
	engine.GET("/health/log-level", h.GetLogLevel)
	engine.PUT("/health/log-level", h.SetLogLevelAPI)
}

func (h *Handler) Health(c *gin.Context) {
	web.Succeed(c).Data(gin.H{
		"status": "ok",
		"uptime": time.Since(startTime).String(),
	}).Send()
}

func (h *Handler) Ready(c *gin.Context) {
	session, err := h.db.GetDBSession()
	if err != nil {
		web.R(c).Code(web.InternalError).HTTP(http.StatusServiceUnavailable).
			Data(gin.H{"status": "not_ready", "error": "database connection failed"}).Send()
		return
	}

	sqlDB, err := session.DB()
	if err != nil {
		web.R(c).Code(web.InternalError).HTTP(http.StatusServiceUnavailable).
			Data(gin.H{"status": "not_ready", "error": "database pool unavailable"}).Send()
		return
	}

	if err := sqlDB.Ping(); err != nil {
		web.R(c).Code(web.InternalError).HTTP(http.StatusServiceUnavailable).
			Data(gin.H{"status": "not_ready", "error": "database ping failed"}).Send()
		return
	}

	web.Succeed(c).Data(gin.H{"status": "ready"}).Send()
}

func (h *Handler) System(c *gin.Context) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	dbStats := map[string]interface{}{}
	if session, err := h.db.GetDBSession(); err == nil {
		if sqlDB, err := session.DB(); err == nil {
			stats := sqlDB.Stats()
			dbStats = map[string]interface{}{
				"open_connections": stats.OpenConnections,
				"in_use":           stats.InUse,
				"idle":             stats.Idle,
				"max_open":         stats.MaxOpenConnections,
				"wait_count":       stats.WaitCount,
				"wait_duration_ms": stats.WaitDuration.Milliseconds(),
			}
		}
	}

	web.Succeed(c).Data(gin.H{
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"go_version":     runtime.Version(),
		"go_arch":        runtime.GOARCH,
		"go_os":          runtime.GOOS,
		"num_goroutines": runtime.NumGoroutine(),
		"num_cpu":        runtime.NumCPU(),
		"memory": gin.H{
			"alloc_mb":          memStats.Alloc / 1024 / 1024,
			"total_alloc_mb":    memStats.TotalAlloc / 1024 / 1024,
			"sys_mb":            memStats.Sys / 1024 / 1024,
			"heap_alloc_mb":     memStats.HeapAlloc / 1024 / 1024,
			"heap_inuse_mb":     memStats.HeapInuse / 1024 / 1024,
			"heap_objects":      memStats.HeapObjects,
			"gc_cycles":         memStats.NumGC,
			"gc_pause_total_ms": memStats.PauseTotalNs / 1e6,
		},
		"database": dbStats,
	}).Send()
}

func (h *Handler) GetLogLevel(c *gin.Context) {
	level := "info"
	if h.logLevel != nil {
		level = h.logLevel.Level().String()
	}
	web.Succeed(c).Data(gin.H{"level": level}).Send()
}

func (h *Handler) SetLogLevelAPI(c *gin.Context) {
	if h.logLevel == nil {
		web.R(c).Code(web.InternalError).HTTP(http.StatusInternalServerError).
			Data(gin.H{"error": "日志级别不可调整"}).Send()
		return
	}

	var req struct {
		Level string `json:"level"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.R(c).Code(web.BadRequest).HTTP(http.StatusBadRequest).
			Data(gin.H{"error": "参数错误"}).Send()
		return
	}

	var newLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(req.Level)) {
	case "debug":
		newLevel = slog.LevelDebug
	case "info":
		newLevel = slog.LevelInfo
	case "warn", "warning":
		newLevel = slog.LevelWarn
	case "error":
		newLevel = slog.LevelError
	default:
		web.R(c).Code(web.BadRequest).HTTP(http.StatusBadRequest).
			Data(gin.H{"error": "无效的日志级别，可选: debug, info, warn, error"}).Send()
		return
	}

	old := h.logLevel.Level().String()
	h.logLevel.Set(newLevel)
	slog.Warn("log level changed", "from", old, "to", newLevel.String())
	web.Succeed(c).Data(gin.H{
		"previous": old,
		"current":  newLevel.String(),
	}).Send()
}
