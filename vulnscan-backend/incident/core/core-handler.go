package core

import (
	coreContract "vulnscan-backend/incident/core/core-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerCore struct {
	svc coreContract.ServiceCore
}

func NewHandlerCore(svc coreContract.ServiceCore) *HandlerCore {
	return &HandlerCore{svc: svc}
}

func (h *HandlerCore) List(c *gin.Context) {
	req, ok := web.BindQuery[coreContract.IncidentListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.ListIncidents(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerCore) Create(c *gin.Context) {
	req, ok := web.BindJSON[coreContract.IncidentCreateReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.CreateIncident(c.Request.Context(), req, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerCore) Detail(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.GetIncidentDetail(c.Request.Context(), uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerCore) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[coreContract.IncidentUpdateReq](c)
	if !ok {
		return
	}
	if err := h.svc.UpdateIncident(c.Request.Context(), uri.Id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerCore) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.DeleteIncident(c.Request.Context(), uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerCore) DashboardStats(c *gin.Context) {
	stats, err := h.svc.GetDashboardStats(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(stats).Send()
}

func (h *HandlerCore) ChartByType(c *gin.Context) {
	items, err := h.svc.GetChartByType(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

func (h *HandlerCore) ChartByTrend(c *gin.Context) {
	query, ok := web.BindQuery[struct {
		RangeType string `form:"range"`
	}](c)
	if !ok {
		return
	}
	items, err := h.svc.GetChartByTrend(c.Request.Context(), query.RangeType)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

func (h *HandlerCore) OplogList(c *gin.Context) {
	query, ok := web.BindQuery[struct {
		IncidentId string `form:"incident_id"`
		IncidentNo string `form:"incident_no"`
	}](c)
	if !ok {
		return
	}
	var items []coreContract.OplogItem
	var err error
	if query.IncidentId != "" {
		items, err = h.svc.GetOplogsByIncidentId(c.Request.Context(), query.IncidentId)
	} else if query.IncidentNo != "" {
		items, err = h.svc.GetOplogsByIncidentNo(c.Request.Context(), query.IncidentNo)
	} else {
		web.Fail(c).Msg("incident_id 或 incident_no 至少提供一个").Send()
		return
	}
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

func (h *HandlerCore) ReceiveOplogCallback(c *gin.Context) {
	req, ok := web.BindJSON[coreContract.OplogCallbackReq](c)
	if !ok {
		return
	}
	if err := h.svc.ReceiveCallbackOplog(c.Request.Context(), req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
