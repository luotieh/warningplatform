package formdesign

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Routes struct {
	handler *Handler
}

func NewRoutes(handler *Handler) *Routes {
	return &Routes{handler: handler}
}

func (r *Routes) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/form"), []authorize.Route{
		{
			Name: "表单中心", Enabled: true,
			Children: []authorize.Route{
				{Name: "模板列表", Path: "templates", Method: "GET", Handler: r.handler.ListTemplates, Enabled: true},
				{Name: "创建模板", Path: "templates", Method: "POST", Handler: r.handler.CreateTemplate, Enabled: true},
				{Name: "模板详情", Path: "templates/:id", Method: "GET", Handler: r.handler.GetTemplate, Enabled: true},
				{Name: "更新模板", Path: "templates/:id", Method: "PUT", Handler: r.handler.UpdateTemplate, Enabled: true},
				{Name: "删除模板", Path: "templates/:id", Method: "DELETE", Handler: r.handler.DeleteTemplate, Enabled: true},
				{Name: "模板版本列表", Path: "templates/:id/versions", Method: "GET", Handler: r.handler.ListVersions, Enabled: true},
				{Name: "模板版本详情", Path: "templates/:id/versions/:versionId", Method: "GET", Handler: r.handler.GetVersion, Enabled: true},
				{Name: "创建模板草稿", Path: "templates/:id/draft", Method: "POST", Handler: r.handler.CreateDraft, Enabled: true},
				{Name: "保存模板草稿", Path: "templates/:id/draft", Method: "PUT", Handler: r.handler.SaveDraft, Enabled: true},
				{Name: "发布模板草稿", Path: "templates/:id/publish", Method: "POST", Handler: r.handler.PublishDraft, Enabled: true},
				{Name: "表单数据列表", Path: "submissions", Method: "GET", Handler: r.handler.ListSubmissions, Enabled: true},
				{Name: "保存表单数据", Path: "submissions", Method: "POST", Handler: r.handler.SaveSubmission, Enabled: true},
				{Name: "表单数据详情", Path: "submissions/:id", Method: "GET", Handler: r.handler.GetSubmission, Enabled: true},
				{Name: "删除表单数据", Path: "submissions/:id", Method: "DELETE", Handler: r.handler.DeleteSubmission, Enabled: true},
			},
		},
	})
}
