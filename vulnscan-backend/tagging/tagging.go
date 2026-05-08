package tagging

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Tagging struct {
	tagHandler       *HandlerTag
	changeLogHandler *HandlerChangeLog
}

func NewTagging(tagHandler *HandlerTag, changeLogHandler *HandlerChangeLog) *Tagging {
	return &Tagging{
		tagHandler:       tagHandler,
		changeLogHandler: changeLogHandler,
	}
}

func (m *Tagging) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/tagging"), []authorize.Route{
		{
			Name: "标签管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "标签列表", Path: "tags/list", Method: "GET", Handler: m.tagHandler.List, Enabled: true},
				{Name: "标签详情", Path: "tags/:id", Method: "GET", Handler: m.tagHandler.GetByID, Enabled: true},
				{Name: "创建标签", Path: "tags", Method: "POST", Handler: m.tagHandler.Create, Enabled: true},
				{Name: "更新标签", Path: "tags/:id", Method: "PUT", Handler: m.tagHandler.Update, Enabled: true},
				{Name: "删除标签", Path: "tags/:id", Method: "DELETE", Handler: m.tagHandler.Delete, Enabled: true},
				{Name: "资产标签", Path: "asset-tags/:asset_id", Method: "GET", Handler: m.tagHandler.GetAssetTags, Enabled: true},
				{Name: "设置资产标签", Path: "asset-tags", Method: "POST", Handler: m.tagHandler.SetAssetTags, Enabled: true},
			},
		},
		{
			Name: "变更日志", Enabled: true,
			Children: []authorize.Route{
				{Name: "变更日志列表", Path: "changelogs/list", Method: "GET", Handler: m.changeLogHandler.List, Enabled: true},
				{Name: "资产变更日志", Path: "changelogs/:asset_id", Method: "GET", Handler: m.changeLogHandler.GetByAssetID, Enabled: true},
			},
		},
	})
}
