package scanrunner

import (
	"encoding/json"
	"strings"

	"vulnscan-backend/model"
	tmplEngine "vulnscan-backend/template/engine"

	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type suggestParamsReq struct {
	TemplateID string   `json:"template_id"`
	Targets    []string `json:"targets"`
}

func (a *API) SuggestParameters(c *gin.Context) {
	req, ok := web.BindJSON[suggestParamsReq](c)
	if !ok {
		return
	}
	n := countTargets(req.Targets)
	resp := SuggestParametersResponse{
		TargetCount: n,
		Derived:     DeriveScanParameters(n),
	}

	if strings.TrimSpace(req.TemplateID) != "" {
		var item model.ScanTemplate
		if err := a.db.Where("id = ? OR code = ?", req.TemplateID, req.TemplateID).First(&item).Error; err == nil && item.Content != "" {
			var parsed tmplEngine.ScanTemplate
			if json.Unmarshal([]byte(item.Content), &parsed) == nil {
				resp.TemplateVersion = parsed.Version
				resp.TemplateOutdated = isTemplateOutdated(parsed)
				ids := make([]string, 0)
				for _, st := range parsed.Stages {
					ids = append(ids, st.GetModuleIDs()...)
				}
				resp.ModuleIDs = ids
				resp.ModuleCount = len(ids)
			}
		}
	}

	web.Succeed(c).Data(resp).Send()
}

func isTemplateOutdated(tmpl tmplEngine.ScanTemplate) bool {
	if tmpl.ID == "full" && tmpl.Version != "" && tmpl.Version < "2.0.0" {
		return true
	}
	// 全量扫描合并后约 7 个模块；明显多于 15 视为旧版
	n := 0
	for _, st := range tmpl.Stages {
		n += len(st.GetModuleIDs())
	}
	return tmpl.ID == "full" && n > 12
}
