package cluster

import (
	"time"

	clusterContract "vulnscan-backend/cluster/cluster-contract"
	"vulnscan-backend/model"

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
	var query clusterContract.WorkerQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	items, count, err := h.svc.ListWorkers(query)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *HandlerCluster) GetWorker(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	node, err := h.svc.GetWorker(id)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}

	web.RespContent(c, web.Success, node)
}

type registerWorkerReq struct {
	ID       string `json:"id" binding:"required"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip" binding:"required"`
	Port     int    `json:"port"`
	Version  string `json:"version"`
	Capacity int    `json:"capacity"`
}

func (h *HandlerCluster) RegisterWorker(c *gin.Context) {
	var req registerWorkerReq
	if !web.ValidationJson(c, &req) {
		return
	}

	node := &model.WorkerNode{
		ID:       req.ID,
		Name:     req.Name,
		Hostname: req.Hostname,
		IP:       req.IP,
		Port:     req.Port,
		Version:  req.Version,
		Capacity: req.Capacity,
	}

	if err := h.svc.RegisterWorker(c.Request.Context(), node); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	token := GenerateWorkerToken(node.ID)

	web.RespContent(c, web.Success, map[string]interface{}{
		"worker": node,
		"token":  token,
	})
}

// Heartbeat returns HeartbeatResponse with pending commands (bidirectional).
func (h *HandlerCluster) Heartbeat(c *gin.Context) {
	var payload clusterContract.HeartbeatPayload
	if !web.ValidationJson(c, &payload) {
		return
	}

	resp, err := h.svc.Heartbeat(c.Request.Context(), &payload)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, resp)
}

func (h *HandlerCluster) UnregisterWorker(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if err := h.svc.UnregisterWorker(c.Request.Context(), id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
}

func (h *HandlerCluster) ReportResult(c *gin.Context) {
	var result clusterContract.TaskResult
	if !web.ValidationJson(c, &result) {
		return
	}

	if err := h.svc.ReportTaskResult(c.Request.Context(), &result); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
}

// PollTask allows workers to pull tasks (atomic claim).
func (h *HandlerCluster) PollTask(c *gin.Context) {
	var req clusterContract.PollTaskRequest
	if !web.ValidationJson(c, &req) {
		return
	}

	slots := req.Slots
	if slots <= 0 {
		slots = 1
	}

	tasks, err := h.svc.PollTask(c.Request.Context(), req.WorkerID, slots)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, tasks)
}

// ReportBan handles IP ban reports from workers.
func (h *HandlerCluster) ReportBan(c *gin.Context) {
	var report clusterContract.BanReport
	if !web.ValidationJson(c, &report) {
		return
	}

	if err := h.svc.ReportBan(c.Request.Context(), &report); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
}

func (h *HandlerCluster) CheckStale(c *gin.Context) {
	stale, err := h.svc.CheckStaleWorkers(c.Request.Context(), 60*time.Second)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, stale)
}
