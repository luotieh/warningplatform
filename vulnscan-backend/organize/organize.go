package organize

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Organize struct {
	orgHandler  *HandlerOrganize
	consHandler *HandlerConstruction
}

func NewOrganize(orgHandler *HandlerOrganize, consHandler *HandlerConstruction) *Organize {
	return &Organize{orgHandler: orgHandler, consHandler: consHandler}
}

func (m *Organize) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/organize"), []authorize.Route{
		{
			Name: "组织管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "组织列表", Path: "list", Method: "GET", Handler: m.orgHandler.List, Enabled: true},
				{Name: "组织树", Path: "tree", Method: "GET", Handler: m.orgHandler.Tree, Enabled: true},
				{Name: "IAM组织树", Path: "iam-tree", Method: "GET", Handler: m.orgHandler.IAMTree, Enabled: true},
				{Name: "组织详情", Path: ":id", Method: "GET", Handler: m.orgHandler.GetByID, Enabled: true},
				{Name: "创建组织", Method: "POST", Handler: m.orgHandler.Create, Enabled: true},
				{Name: "更新组织", Path: ":id", Method: "PUT", Handler: m.orgHandler.Update, Enabled: true},
				{Name: "删除组织", Path: ":id", Method: "DELETE", Handler: m.orgHandler.Delete, Enabled: true},
				{Name: "同步IAM组织", Path: "sync-iam", Method: "POST", Handler: m.orgHandler.SyncIam, Enabled: true},
				{Name: "确保组织存在", Path: "ensure", Method: "POST", Handler: m.orgHandler.Ensure, Enabled: true},
			},
		},
		{
			Name: "建设运维单位", Path: "construction", Enabled: true,
			Children: []authorize.Route{
				{Name: "单位列表", Path: "list", Method: "GET", Handler: m.consHandler.List, Enabled: true},
				{Name: "单位详情", Path: ":id", Method: "GET", Handler: m.consHandler.GetByID, Enabled: true},
				{Name: "创建单位", Method: "POST", Handler: m.consHandler.Create, Enabled: true},
				{Name: "更新单位", Path: ":id", Method: "PUT", Handler: m.consHandler.Update, Enabled: true},
				{Name: "删除单位", Path: ":id", Method: "DELETE", Handler: m.consHandler.Delete, Enabled: true},
			},
		},
	})
}
