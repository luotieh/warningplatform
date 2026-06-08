package scanrunner

import (
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

func (a *API) ListEngineRules(c *gin.Context) {
	web.Succeed(c).Data(map[string]interface{}{
		"rules":              EngineRulesCatalog(),
		"module_exposure":    PrimaryModuleExposureDoc(),
		"primary_module_ids": PrimaryModuleIDs(),
	}).Send()
}

func (a *API) TaskParameterSchema(c *gin.Context) {
	web.Succeed(c).Data(map[string]interface{}{
		"task_level_params":    TaskLevelParamsCatalog(),
		"module_create_params": ModuleCreateParamsCatalog(),
		"engine_presets":       ListScanEnginePresets(),
	}).Send()
}
