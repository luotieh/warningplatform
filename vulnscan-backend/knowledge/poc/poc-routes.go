package poc

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Poc struct {
	handler *HandlerPoc
}

func NewPoc(handler *HandlerPoc) *Poc {
	return &Poc{handler: handler}
}

func (m *Poc) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/poc"), []authorize.Route{
		{
			Name: "POC管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "POC列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "POC详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建POC", Path: "", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新POC", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除POC", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "启停POC", Path: ":id/toggle", Method: "POST", Handler: m.handler.Toggle, Enabled: true},
				{Name: "导入YAML", Path: "import", Method: "POST", Handler: m.handler.ImportYAML, Enabled: true},
				{Name: "目录导入", Path: "import-dir", Method: "POST", Handler: m.handler.ImportDir, Enabled: true},
				{Name: "校验YAML", Path: "validate", Method: "POST", Handler: m.handler.Validate, Enabled: true},
				{Name: "测试POC", Path: "test", Method: "POST", Handler: m.handler.TestPoc, Enabled: true},
			},
		},
	})
}
