package cluster

import (
	"time"

	clusterContract "vulnscan-backend/cluster/cluster-contract"
	"vulnscan-backend/pkg/clusterconn"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type HandlerCluster struct {
	svc  clusterContract.ServiceCluster
	conn clusterconn.Options
}

func NewHandlerCluster(svc clusterContract.ServiceCluster, conn clusterconn.Options) *HandlerCluster {
	return &HandlerCluster{svc: svc, conn: conn}
}

func (h *HandlerCluster) GetConnectivityModes(c *gin.Context) {
	web.OK(c).Data(clusterconn.BuildConnectivityModes(h.conn)).Send()
}

func (h *HandlerCluster) IssueScanNodeCredentials(c *gin.Context) {
	req, ok := web.BindJSON[clusterContract.NodeEnrollmentIssueRequest](c)
	if !ok {
		return
	}

	out, err := h.svc.IssueScanNodeCredentials(c.Request.Context(), &req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(out).Send()
}

func (h *HandlerCluster) ListWorkers(c *gin.Context) {
	query, ok := web.BindQuery[clusterContract.WorkerQuery](c)
	if !ok {
		return
	}

	items, count, err := h.svc.ListWorkers(query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).List(count, items).Send()
}

func (h *HandlerCluster) GetWorker(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	node, err := h.svc.GetWorker(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	web.OK(c).Data(node).Send()
}

func (h *HandlerCluster) NodeKnowledgeManifest(c *gin.Context) {
	data, err := h.svc.KnowledgeManifest(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(data).Send()
}

func (h *HandlerCluster) CheckStale(c *gin.Context) {
	stale, err := h.svc.CheckStaleWorkers(c.Request.Context(), 60*time.Second)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(stale).Send()
}
