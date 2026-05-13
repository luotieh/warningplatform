package nodeapi

import (
	"time"

	"code.yt-security.com/public/core/v2/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type NodeAPI struct {
	db            *db.DB
	monitorResult MonitorResultHandler
	scanResult    ScanResultHandler
}

type MonitorResultHandler interface {
	HandleMonitorResult(executionID, status, errMsg, result, startedAt, finishedAt string)
}

type ScanResultHandler interface {
	HandleScanResult(taskID, status, errMsg string, progress float64, resultJSON string, finishedAt *time.Time)
}

func New(database *db.DB, monitorHandler MonitorResultHandler, scanHandler ScanResultHandler) *NodeAPI {
	return &NodeAPI{
		db:            database,
		monitorResult: monitorHandler,
		scanResult:    scanHandler,
	}
}

func (a *NodeAPI) gdb() *gorm.DB {
	s, _ := a.db.GetDBSession()
	return s
}

func (a *NodeAPI) RegisterRoutes(e *gin.Engine, pathPrefix string) {
	g := e.Group(pathPrefix + "/node-api")
	g.Use(a.authMiddleware())

	g.POST("/heartbeat", a.Heartbeat)
	g.GET("/tasks/poll", a.PollTasks)
	g.POST("/tasks/result", a.ReportResult)
	g.GET("/rules", a.GetRules)
	g.GET("/commands/poll", a.PollCommands)
}
