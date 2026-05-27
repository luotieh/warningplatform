package scanrunner

import (
	"strings"

	"vulnscan-backend/scan/core"
	"vulnscan-backend/template/engine"

	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type PipelineAPI struct {
	db      *gorm.DB
	factory *ModuleFactory
}

func NewPipelineAPI(db *gorm.DB) *PipelineAPI {
	return &PipelineAPI{db: db, factory: NewModuleFactory(db)}
}

type ModuleInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

type StageInfo struct {
	Name    string       `json:"name"`
	Modules []ModuleInfo `json:"modules"`
}

func (a *PipelineAPI) RoutesWithGroup(g *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(g.Group("/pipeline"), []authorize.Route{
		{
			Name: "扫描流水线", Enabled: true,
			Children: []authorize.Route{
				{Name: "模块列表", Path: "modules", Method: "GET", Handler: a.ListModules, Enabled: true},
				{Name: "模块配置", Path: "modules/config", Method: "GET", Handler: a.ListModuleConfigs, Enabled: true},
				{Name: "流水线模板", Path: "templates", Method: "GET", Handler: a.ListTemplates, Enabled: true},
			},
		},
	})
}

func (a *PipelineAPI) RegisterRoutes(g *gin.RouterGroup) {
	a.RoutesWithGroup(g)
}

func (a *PipelineAPI) ListModules(c *gin.Context) {
	ids := PrimaryModuleIDs()
	if c.Query("legacy") == "1" {
		ids = a.factory.AllIDs()
	}
	var result []ModuleInfo
	for _, id := range ids {
		m := a.factory.Build(id)
		if m != nil {
			result = append(result, ModuleInfo{
				ID:       m.ID(),
				Name:     m.Name(),
				Category: m.Category(),
			})
		}
	}
	web.OK(c).Data(result).Send()
}

func (a *PipelineAPI) ListModuleConfigs(c *gin.Context) {
	ids := PrimaryModuleIDs()
	if c.Query("legacy") == "1" {
		ids = a.factory.AllIDs()
	}
	if raw := c.Query("module_ids"); raw != "" {
		ids = strings.Split(raw, ",")
	}
	var configs []core.ModuleConfigInfo
	for _, id := range ids {
		m := a.factory.Build(id)
		if m != nil {
			if c.Query("legacy") == "1" {
				configs = append(configs, core.GetModuleConfigInfo(m))
			} else {
				configs = append(configs, core.GetExposedModuleConfigInfo(m))
			}
		}
	}
	web.OK(c).Data(configs).Send()
}

func (a *PipelineAPI) ListTemplates(c *gin.Context) {
	builtins := engine.BuiltinTemplates()
	type templateSummary struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		StageCount  int      `json:"stage_count"`
		ModuleCount int      `json:"module_count"`
	}

	var result []templateSummary
	for _, t := range builtins {
		moduleCount := 0
		for _, s := range t.Stages {
			moduleCount += len(s.GetModuleIDs())
		}
		result = append(result, templateSummary{
			ID:          t.ID,
			Name:        t.Name,
			Description: t.Description,
			Tags:        t.Tags,
			StageCount:  len(t.Stages),
			ModuleCount: moduleCount,
		})
	}
	web.OK(c).Data(result).Send()
}
