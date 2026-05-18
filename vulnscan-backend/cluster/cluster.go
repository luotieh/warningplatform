package cluster

import (
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Cluster struct {
	handler *HandlerCluster
}

func NewCluster(handler *HandlerCluster, database *db.DB) *Cluster {
	initModel(database)
	return &Cluster{handler: handler}
}

func (m *Cluster) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/cluster"), []authorize.Route{
		{
			Name: "集群管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "Worker列表", Path: "workers", Method: "GET", Handler: m.handler.ListWorkers, Enabled: true},
				{Name: "Worker详情", Path: "workers/:id", Method: "GET", Handler: m.handler.GetWorker, Enabled: true},
				{Name: "节点知识库版本", Path: "node-knowledge/manifest", Method: "GET", Handler: m.handler.NodeKnowledgeManifest, Enabled: true},
				{Name: "部署拓扑说明", Path: "connectivity-modes", Method: "GET", Handler: m.handler.GetConnectivityModes, Enabled: true},
				{Name: "签发扫描节点凭据", Path: "scan-nodes/enroll", Method: "POST", Handler: m.handler.IssueScanNodeCredentials, Enabled: true},
				{Name: "检查失联", Path: "workers/check-stale", Method: "POST", Handler: m.handler.CheckStale, Enabled: true},
			},
		},
	})
}

func initModel(database *db.DB) {
	session, _ := database.GetDBSession()
	_ = session.AutoMigrate(&model.WorkerNode{})
}
