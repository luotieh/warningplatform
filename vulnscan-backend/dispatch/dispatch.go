package dispatch

import (
	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/core/db"
	"github.com/gin-gonic/gin"
	"github.com/google/wire"

	dispatchContract "vulnscan-backend/dispatch/dispatch-contract"
)

var WireSet = wire.NewSet(
	NewOrderService,
	NewContactService,
	NewOrderHandler,
	NewContactHandler,
	NewDispatch,
	wire.Bind(new(dispatchContract.ServiceOrder), new(*orderService)),
	wire.Bind(new(dispatchContract.ServiceContact), new(*contactService)),
)

type Dispatch struct {
	orderHandler   *OrderHandler
	contactHandler *ContactHandler
}

func NewDispatch(
	orderHandler *OrderHandler,
	contactHandler *ContactHandler,
	database *db.DB,
) *Dispatch {
	return &Dispatch{
		orderHandler:   orderHandler,
		contactHandler: contactHandler,
	}
}

func (d *Dispatch) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/dispatch"), []authorize.Route{
		{
			Name: "派发单管理", Path: "orders", Enabled: true,
			Children: []authorize.Route{
				{Name: "派发单列表", Method: "GET", Handler: d.orderHandler.List, Enabled: true},
				{Name: "创建派发单", Method: "POST", Handler: d.orderHandler.Create, Enabled: true},
				{Name: "派发单详情", Path: ":id", Method: "GET", Handler: d.orderHandler.Detail, Enabled: true},
				{Name: "取消派发单", Path: ":id/cancel", Method: "POST", Handler: d.orderHandler.Cancel, Enabled: true},
				{Name: "指派处理人", Path: ":id/assign", Method: "POST", Handler: d.orderHandler.Assign, Enabled: true},
				{Name: "接收派发单", Path: ":id/accept", Method: "POST", Handler: d.orderHandler.Accept, Enabled: true},
				{Name: "拒绝派发单", Path: ":id/reject", Method: "POST", Handler: d.orderHandler.Reject, Enabled: true},
				{Name: "提交结果", Path: ":id/submit", Method: "POST", Handler: d.orderHandler.SubmitResult, Enabled: true},
				{Name: "审核结果", Path: ":id/review", Method: "POST", Handler: d.orderHandler.Review, Enabled: true},
				{Name: "操作日志", Path: ":id/oplogs", Method: "GET", Handler: d.orderHandler.Oplogs, Enabled: true},
			},
		},
		{
			Name: "统计分析", Path: "stats", Enabled: true,
			Children: []authorize.Route{
				{Name: "派发统计概览", Method: "GET", Handler: d.orderHandler.Stats, Enabled: true},
			},
		},
		{
			Name: "外部联系人", Path: "contacts", Enabled: true,
			Children: []authorize.Route{
				{Name: "联系人列表", Method: "GET", Handler: d.contactHandler.List, Enabled: true},
				{Name: "创建联系人", Method: "POST", Handler: d.contactHandler.Create, Enabled: true},
				{Name: "联系人详情", Path: ":id", Method: "GET", Handler: d.contactHandler.Detail, Enabled: true},
				{Name: "更新联系人", Path: ":id", Method: "PUT", Handler: d.contactHandler.Update, Enabled: true},
				{Name: "删除联系人", Path: ":id", Method: "DELETE", Handler: d.contactHandler.Delete, Enabled: true},
			},
		},
	})
}
