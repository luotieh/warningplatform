package nodeapi

import (
	"os"
	"strings"
	"sync"
	"time"

	"code.yt-security.com/public/core/v2/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	fedSync "vulnscan-backend/federation/sync"
)

// Options configures node-api authentication behavior.
type Options struct {
	// RequireAgentSecret rejects any node whose AgentSecretHash is empty (HTTP 403).
	// Enable after all vs_nodes rows have been issued secrets (env VULNSCAN_NODEAPI_REQUIRE_AGENT_SECRET=true).
	RequireAgentSecret bool
}

type NodeAPI struct {
	db            *db.DB
	monitorResult MonitorResultHandler
	scanResult    ScanResultHandler
	opts          Options

	knowledgeMu sync.Mutex
	knowledgeVM *fedSync.VersionManager
}

type MonitorResultHandler interface {
	HandleMonitorResult(executionID, agentID, status, errMsg, result, startedAt, finishedAt string)
}

type ScanResultHandler interface {
	HandleScanResult(taskID, status, errMsg string, progress float64, resultJSON string, finishedAt *time.Time)
}

func New(database *db.DB, monitorHandler MonitorResultHandler, scanHandler ScanResultHandler, opts Options) *NodeAPI {
	return &NodeAPI{
		db:            database,
		monitorResult: monitorHandler,
		scanResult:    scanHandler,
		opts:          opts,
	}
}

// OptionsFromEnv builds Options from process environment.
func OptionsFromEnv() Options {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("VULNSCAN_NODEAPI_REQUIRE_AGENT_SECRET")))
	return Options{
		RequireAgentSecret: v == "1" || v == "true" || v == "yes",
	}
}

func (a *NodeAPI) gdb() *gorm.DB {
	s, _ := a.db.GetDBSession()
	return s
}

func (a *NodeAPI) RegisterRoutes(e *gin.Engine, pathPrefix string) {
	base := pathPrefix + "/node-api"
	e.GET(base+"/health", a.Health)

	g := e.Group(base)
	g.Use(a.authMiddleware())

	g.POST("/heartbeat", a.Heartbeat)
	g.GET("/tasks/poll", a.PollTasks)
	g.POST("/tasks/result", a.ReportResult)
	g.GET("/rules", a.GetRules)
	g.GET("/knowledge/manifest", a.KnowledgeManifest)
	g.GET("/knowledge/sync/poc", a.KnowledgeSyncPoc)
	g.GET("/knowledge/sync/fingerprint", a.KnowledgeSyncFingerprint)
	g.GET("/knowledge/sync/rule", a.KnowledgeSyncRule)
	g.GET("/commands/poll", a.PollCommands)
}
