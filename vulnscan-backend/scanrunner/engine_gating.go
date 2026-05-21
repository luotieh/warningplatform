package scanrunner

import (
	"log/slog"
	"strings"

	"vulnscan-backend/scan/core"
)

// configKeySkipWebModules 写入运行配置，供 ExecuteStageWithOpts 过滤 Web 漏洞类模块（不入库、不传给模块）。
const configKeySkipWebModules = "engine_skip_web_modules"

// webVulnModuleIDs 无明确 HTTP 服务时可跳过的 Web 向模块（含合并后的组合模块 ID）。
var webVulnModuleIDs = map[string]struct{}{
	"web_vuln_scan": {},
	"sqli":          {}, "xss": {}, "ssrf": {}, "cmdi": {}, "lfi": {}, "ssti": {}, "xxe": {}, "nosqli": {},
	"jwt_sec": {}, "apisec": {}, "dir_scan": {}, "advanced_vuln": {}, "fpenhance": {},
}

func hasHTTPFromStageContext(ctx *StageContext) bool {
	if ctx == nil {
		return false
	}
	for _, r := range ctx.CompletedStages {
		for _, f := range r.Findings {
			if f == nil {
				continue
			}
			if f.ModuleID == "service_probe" && f.Type == "service" {
				if f.Target != nil {
					proto := strings.ToLower(f.Target.Protocol)
					if strings.Contains(proto, "http") {
						return true
					}
				}
				if f.Data != nil {
					if svc, ok := f.Data["service"]; ok && strings.Contains(strings.ToLower(svc), "http") {
						return true
					}
				}
			}
			if f.Type == "port_open" && f.Target != nil {
				switch f.Target.Port {
				case 80, 443, 8000, 8080, 8443, 8888:
					return true
				}
			}
			if f.Target != nil && strings.Contains(strings.ToLower(f.Target.URL), "http") {
				return true
			}
		}
	}
	return false
}

func (r *Runner) applyEngineRuntimeGating(config map[string]interface{}, stageCtx *StageContext) {
	if config == nil || stageCtx == nil {
		return
	}
	if !r.enginePolicy.AutoSkipWebVulnsWithoutHTTP {
		delete(config, configKeySkipWebModules)
		return
	}
	if hasHTTPFromStageContext(stageCtx) {
		delete(config, configKeySkipWebModules)
		return
	}
	config[configKeySkipWebModules] = true
}

func filterWebVulnModules(mods []core.ScanModule, config map[string]interface{}) []core.ScanModule {
	if config == nil {
		return mods
	}
	v, ok := config[configKeySkipWebModules].(bool)
	if !ok || !v {
		return mods
	}
	out := make([]core.ScanModule, 0, len(mods))
	for _, m := range mods {
		if _, skip := webVulnModuleIDs[m.ID()]; skip {
			continue
		}
		out = append(out, m)
	}
	if len(out) < len(mods) {
		slog.Info("[Engine] 已跳过 Web 漏洞模块（未发现 HTTP/HTTPS 服务）",
			"removed", len(mods)-len(out))
	}
	return out
}

func filterTargetsForExclusions(f *FindingFilter, targets []*core.Target) []*core.Target {
	if f == nil || len(targets) == 0 {
		return targets
	}
	out := targets[:0]
	for _, t := range targets {
		host := strings.TrimSpace(t.Host)
		if host == "" {
			host = strings.TrimSpace(t.IP)
		}
		if host == "" {
			continue
		}
		port := 0
		if t != nil {
			port = t.Port
		}
		if f.ShouldExcludeTarget(host, port) {
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
