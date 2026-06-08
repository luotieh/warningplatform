package fingerprint

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type Fingerprint struct {
	handler    *HandlerFingerprint
	webHandler *HandlerWebFingerprint
}

func NewFingerprint(handler *HandlerFingerprint) *Fingerprint {
	return &Fingerprint{handler: handler}
}

func NewFingerprintFull(handler *HandlerFingerprint, webHandler *HandlerWebFingerprint) *Fingerprint {
	return &Fingerprint{handler: handler, webHandler: webHandler}
}

func (m *Fingerprint) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	routes := []authorize.Route{
		{
			Name: "服务识别指纹", Enabled: true,
			Children: []authorize.Route{
				{Name: "服务指纹列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "服务指纹详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建服务指纹", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新服务指纹", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除服务指纹", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
			},
		},
	}

	var items []authorize.BackendItem
	items = append(items, authorize.RegisterRoutes(e.Group("/fingerprint"), routes)...)

	if m.webHandler != nil {
		webRoutes := []authorize.Route{
			{
				Name: "Web识别指纹", Enabled: true,
				Children: []authorize.Route{
					{Name: "Web指纹列表", Method: "GET", Handler: m.webHandler.List, Enabled: true},
					{Name: "Web指纹详情", Path: ":id", Method: "GET", Handler: m.webHandler.GetByID, Enabled: true},
					{Name: "创建Web指纹", Method: "POST", Handler: m.webHandler.Create, Enabled: true},
					{Name: "更新Web指纹", Path: ":id", Method: "PUT", Handler: m.webHandler.Update, Enabled: true},
					{Name: "删除Web指纹", Path: ":id", Method: "DELETE", Handler: m.webHandler.Delete, Enabled: true},
				},
			},
		}
		items = append(items, authorize.RegisterRoutes(e.Group("/web-fingerprints"), webRoutes)...)
	}

	return items
}
