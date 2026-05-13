package cluster

import (
	"time"

	clusterContract "vulnscan-backend/cluster/cluster-contract"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type HandlerCluster struct {
	svc clusterContract.ServiceCluster
}

func NewHandlerCluster(svc clusterContract.ServiceCluster) *HandlerCluster {
	return &HandlerCluster{svc: svc}
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

func (h *HandlerCluster) CheckStale(c *gin.Context) {
	stale, err := h.svc.CheckStaleWorkers(c.Request.Context(), 60*time.Second)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(stale).Send()
}
