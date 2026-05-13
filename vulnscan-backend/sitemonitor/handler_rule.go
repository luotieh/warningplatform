package sitemonitor

import (
	"encoding/json"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

// ══ 规则数据 ══

func (h *HandlerMonitor) ListRuleDataSummary(c *gin.Context) {
	list, err := h.svc.ListRuleDataSummary(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(list).Send()
}

func (h *HandlerMonitor) GetRuleData(c *gin.Context) {
	moduleKey := c.Param("moduleKey")
	data, err := h.svc.GetRuleData(c.Request.Context(), moduleKey)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(data).Send()
}

func (h *HandlerMonitor) PutRuleData(c *gin.Context) {
	moduleKey := c.Param("moduleKey")
	var req struct {
		Data string `json:"data" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.PutRuleData(c.Request.Context(), moduleKey, req.Data); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) SyncAllRuleData(c *gin.Context) {
	if err := h.svc.SyncAllRuleData(c.Request.Context()); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) ImportRuleData(c *gin.Context) {
	moduleKey := c.Param("moduleKey")
	if _, ok := model.MonitorModuleRegistry[moduleKey]; !ok {
		web.Fail(c).Msg("未知模块: " + moduleKey).Send()
		return
	}

	var req struct {
		Data  json.RawMessage `json:"data" binding:"required"`
		Merge bool            `json:"merge"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	var incoming map[string]any
	if err := json.Unmarshal(req.Data, &incoming); err != nil {
		web.Fail(c).Msg("JSON 格式无效: " + err.Error()).Send()
		return
	}

	if req.Merge {
		existing, _ := h.svc.GetRuleData(c.Request.Context(), moduleKey)
		if existing != nil && existing.Data != "" {
			var existingData map[string]any
			if err := json.Unmarshal([]byte(existing.Data), &existingData); err == nil {
				for key, val := range incoming {
					inArr, ok1 := val.([]any)
					exArr, ok2 := existingData[key].([]any)
					if ok1 && ok2 {
						existingData[key] = append(exArr, inArr...)
					} else {
						existingData[key] = val
					}
				}
				incoming = existingData
			}
		}
	}

	merged, _ := json.Marshal(incoming)
	if err := h.svc.PutRuleData(c.Request.Context(), moduleKey, string(merged)); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"module_key": moduleKey, "sections": len(incoming)}).Send()
}

func (h *HandlerMonitor) ResetDefaultRuleData(c *gin.Context) {
	InitDefaultRuleData(h.svc.GetDB())
	web.OK(c).Msg("默认规则数据已重置").Send()
}

// ══ 告警配置 ══

func (h *HandlerMonitor) GetAlertConfig(c *gin.Context) {
	cfg, err := h.svc.GetAlertConfig(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(cfg).Send()
}

func (h *HandlerMonitor) UpdateAlertConfig(c *gin.Context) {
	var cfg model.MonitorAlertConfig
	if !web.ValidationJson(c, &cfg) {
		return
	}
	if err := h.svc.UpdateAlertConfig(c.Request.Context(), &cfg); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ══ Agent ══

func (h *HandlerMonitor) ListAgents(c *gin.Context) {
	agents, err := h.svc.ListAgents(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(agents).Send()
}

func (h *HandlerMonitor) SyncAgentRules(c *gin.Context) {
	uuid := c.Param("uuid")
	result, err := h.svc.SyncAgentRules(c.Request.Context(), uuid)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}

func (h *HandlerMonitor) ShutdownAgent(c *gin.Context) {
	uuid := c.Param("uuid")
	result, err := h.svc.ShutdownAgent(c.Request.Context(), uuid)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}
