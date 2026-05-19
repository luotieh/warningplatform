package sitemonitor

import (
	"context"
	"encoding/json"
	"strings"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// BuildMonitorTaskMessage 构造下发给 Agent 的任务载荷。
func BuildMonitorTaskMessage(ctx context.Context, db *gorm.DB, exec *model.MonitorExecution) (*model.MonitorTaskMessage, error) {
	runCtx, err := loadMonitorRunContext(db.WithContext(ctx), exec)
	if err != nil {
		return nil, err
	}

	var cfg model.JSONMap
	if runCtx.PathTask != nil {
		cfg, err = pathConfigForRun(runCtx.PathTask, exec.Dimension)
	} else {
		cfg, err = targetConfigForRun(runCtx.Target, exec.Dimension)
	}
	if err != nil {
		return nil, err
	}

	agentCfg, err := buildAgentConfigForDimension(ctx, db, runCtx, exec.Dimension, cfg)
	if err != nil {
		return nil, err
	}

	msg := &model.MonitorTaskMessage{
		ExecutionID: exec.ID,
		TargetID:    runCtx.Target.ID,
		Dimension:   exec.Dimension,
		URL:         runCtx.Endpoint.RequestURL,
		RequestHost: runCtx.Endpoint.RequestHost,
		Config:      agentCfg,
	}
	if runCtx.PathTask != nil {
		msg.PathTaskID = runCtx.PathTask.ID
	}

	if exec.Dimension == "tamper" {
		bl, err := GetActiveBaseline(ctx, db, runCtx.Endpoint.DisplayURL)
		if err == nil && bl != nil && strings.TrimSpace(bl.BodyText) != "" {
			msg.Baseline = baselineToMetadata(bl)
		}
	}

	return msg, nil
}

func buildAgentConfigForDimension(ctx context.Context, db *gorm.DB, runCtx *MonitorRunContext, dimension string, cfg map[string]any) (map[string]any, error) {
	agentCfg := make(map[string]any)
	target := runCtx.Target

	switch dimension {
	case "availability":
		agentCfg["timeout"] = toInt(cfg["timeout_seconds"])
		agentCfg["method"] = "GET"
		agentCfg["follow_redirects"] = true
		if codes, _ := cfg["exclude_status_codes"].(string); codes != "" {
			var intCodes []int
			for _, c := range strings.Split(codes, ";") {
				if n := toInt(strings.TrimSpace(c)); n > 0 {
					intCodes = append(intCodes, n)
				}
			}
			agentCfg["exclude_codes"] = intCodes
		}
		if target.ExpectedIPs != "" {
			agentCfg["expected_ips"] = strings.Split(target.ExpectedIPs, ",")
		}
	case "domain_hijack":
		if target.ExpectedIPs != "" {
			ips := strings.Split(target.ExpectedIPs, ",")
			agentCfg["expected_ip"] = strings.TrimSpace(ips[0])
		}
	case "tamper":
		if v, ok := cfg["search_engine_ua"]; ok {
			agentCfg["use_search_ua"] = v
		}
		agentCfg["update_baseline"] = false
	case "sensitive_word":
		wlIDs := extractStringSlice(cfg, "word_library_ids")
		if len(wlIDs) == 0 {
			var libs []model.MonitorWordLibrary
			if err := db.WithContext(ctx).Find(&libs).Error; err == nil {
				wlIDs = make([]string, 0, len(libs))
				for _, lib := range libs {
					wlIDs = append(wlIDs, lib.ID)
				}
			}
		}
		agentCfg["word_library_ids"] = wlIDs
		var categories []model.MonitorWordCategory
		if err := db.WithContext(ctx).Where("library_id IN ?", wlIDs).Find(&categories).Error; err == nil {
			names := make([]string, 0, len(categories))
			for _, c := range categories {
				names = append(names, c.Name)
			}
			if len(names) > 0 {
				agentCfg["word_categories"] = names
			}
		}
	case "sensitive_file":
		flIDs := extractStringSlice(cfg, "file_library_ids")
		agentCfg["file_library_ids"] = flIDs
		var libs []model.MonitorFileLibrary
		if err := db.WithContext(ctx).Where("id IN ?", flIDs).Find(&libs).Error; err == nil {
			groups := make([]string, 0, len(libs))
			for _, l := range libs {
				groups = append(groups, l.Name)
			}
			if len(groups) > 0 {
				agentCfg["file_groups"] = groups
			}
		}
	case "blacklink":
		agentCfg["scan_js_files"] = true
		agentCfg["static_compare"] = true
		agentCfg["max_js_files"] = 30
	}

	return agentCfg, nil
}

// MarshalMonitorPayload 序列化为 Agent 可解析的 JSON。
func MarshalMonitorPayload(msg *model.MonitorTaskMessage) ([]byte, error) {
	return json.Marshal(msg)
}
