package nuclei

import (
	"os"
	"strings"
	"time"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
)

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// mergeInteractshNucleiOptions 合并 Interactsh 相关 SDK 选项（自建 OOB、禁用 OOB、轮询间隔等）。
// 优先级：nuclei_interactsh_disable → 任务参数 nuclei_interactsh_server / url + token → 环境变量 VULNSCAN_NUCLEI_INTERACTSH_URL / TOKEN。
func mergeInteractshNucleiOptions(opts []nucleilib.NucleiSDKOptions, config map[string]interface{}) []nucleilib.NucleiSDKOptions {
	if config == nil {
		return opts
	}
	if boolFromConfig(config, "nuclei_interactsh_disable") {
		o := nucleilib.InteractshOpts{NoInteractsh: true, CacheSize: 5000}
		return append(opts, nucleilib.WithInteractshOptions(o))
	}

	server := firstNonEmptyString(
		configString(config, "nuclei_interactsh_server", ""),
		configString(config, "nuclei_interactsh_url", ""),
		strings.TrimSpace(os.Getenv("VULNSCAN_NUCLEI_INTERACTSH_URL")),
	)
	auth := firstNonEmptyString(
		configString(config, "nuclei_interactsh_token", ""),
		configString(config, "nuclei_interactsh_authorization", ""),
		strings.TrimSpace(os.Getenv("VULNSCAN_NUCLEI_INTERACTSH_TOKEN")),
	)
	if server == "" {
		return opts
	}

	o := nucleilib.InteractshOpts{
		ServerURL:      server,
		Authorization:  auth,
		CacheSize:      5000,
		Eviction:       60 * time.Second,
		CooldownPeriod: 5 * time.Second,
		PollDuration:   5 * time.Second,
	}
	if sec := intFromConfig(config, "nuclei_interactsh_poll_seconds", 0); sec > 0 {
		o.PollDuration = time.Duration(sec) * time.Second
	}
	if sec := intFromConfig(config, "nuclei_interactsh_eviction_seconds", 0); sec > 0 {
		o.Eviction = time.Duration(sec) * time.Second
	}
	if sec := intFromConfig(config, "nuclei_interactsh_cooldown_seconds", 0); sec > 0 {
		o.CooldownPeriod = time.Duration(sec) * time.Second
	}
	return append(opts, nucleilib.WithInteractshOptions(o))
}
