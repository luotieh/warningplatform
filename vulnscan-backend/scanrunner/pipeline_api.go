package scanrunner

import (
	"vulnscan-backend/dict"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/rulestore"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type PipelineAPI struct {
	db     *gorm.DB
	loader *payload.Loader
}

func NewPipelineAPI(db *gorm.DB, loader *payload.Loader) *PipelineAPI {
	return &PipelineAPI{db: db, loader: loader}
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

func (a *PipelineAPI) RegisterRoutes(g *gin.RouterGroup) {
	pg := g.Group("/pipeline")
	{
		pg.GET("/modules", a.ListModules)
		pg.GET("/modules/config", a.ListModuleConfigs)
		pg.GET("/stages", a.ListStages)
		pg.GET("/profiles", a.ListProfiles)
	}
}

func (a *PipelineAPI) ListModules(c *gin.Context) {
	ds := dict.NewStore(nil)
	rs := rulestore.NewWithoutDB()
	mods := allModules(a.db, rs, ds, a.loader)

	var result []ModuleInfo
	for _, m := range mods {
		result = append(result, ModuleInfo{
			ID:       m.ID(),
			Name:     m.Name(),
			Category: m.Category(),
		})
	}

	web.OK(c).Data(result).Send()
}

func (a *PipelineAPI) ListStages(c *gin.Context) {
	ds := dict.NewStore(nil)
	rs := rulestore.NewWithoutDB()
	mods := allModules(a.db, rs, ds, a.loader)
	stages := BuildStages(mods)

	var result []StageInfo
	for _, s := range stages {
		si := StageInfo{Name: s.name}
		for _, m := range s.modules {
			si.Modules = append(si.Modules, ModuleInfo{
				ID:       m.ID(),
				Name:     m.Name(),
				Category: m.Category(),
			})
		}
		result = append(result, si)
	}

	web.OK(c).Data(result).Send()
}

func (a *PipelineAPI) ListModuleConfigs(c *gin.Context) {
	ds := dict.NewStore(nil)
	rs := rulestore.NewWithoutDB()
	mods := allModules(a.db, rs, ds, a.loader)

	var configs []core.ModuleConfigInfo
	for _, m := range mods {
		configs = append(configs, core.GetModuleConfigInfo(m))
	}

	web.OK(c).Data(configs).Send()
}

func (a *PipelineAPI) ListProfiles(c *gin.Context) {
	profiles := []gin.H{
		{"id": "quick", "name": "快速扫描", "description": "ICMP + 端口 + 服务 + 爬虫", "modules_count": 4},
		{"id": "recon", "name": "信息收集", "description": "全量信息收集 + 技术检测", "modules_count": 21},
		{"id": "vuln", "name": "漏洞检测", "description": "SQLi + XSS + CMDi + LFI + SSRF + SSTI + XXE + NoSQLi + JWT + 弱口令 + 爆破", "modules_count": 12},
		{"id": "vuln-full", "name": "深度漏洞扫描", "description": "包含所有漏洞检测模块 + API安全检测", "modules_count": 13},
		{"id": "full", "name": "全量扫描", "description": "所有模块全量执行", "modules_count": 35},
	}
	web.OK(c).Data(profiles).Send()
}
