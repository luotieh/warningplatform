package nuclei

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"gorm.io/gorm"

	"vulnscan-backend/pkg/scanmetrics"
	"vulnscan-backend/scan/core"
)

type NucleiModule struct {
	store *PocStore
}

func NewModule(db *gorm.DB) *NucleiModule {
	return NewModuleWithStore(db, NewPocStore(db))
}

// NewModuleWithStore 使用共享 PocStore（与知识库 PoC API 同一缓存，支持热重载）。
func NewModuleWithStore(db *gorm.DB, store *PocStore) *NucleiModule {
	if store == nil {
		store = NewPocStore(db)
	}
	return &NucleiModule{store: store}
}

func NewModuleWithoutDB() *NucleiModule {
	return &NucleiModule{
		store: NewPocStoreNoDB(),
	}
}

func (m *NucleiModule) ID() string       { return "nuclei-poc" }
func (m *NucleiModule) Name() string     { return "Nuclei PoC Scanner" }
func (m *NucleiModule) Category() string { return "vuln" }

func (m *NucleiModule) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	mc := &struct {
		mode     string
		outcome  string
		findings int
	}{outcome: "success"}
	defer func() {
		mode := mc.mode
		if mode == "" {
			mode = "unknown"
		}
		scanmetrics.RecordNucleiRun(mode, mc.outcome, time.Since(start).Seconds(), mc.findings)
	}()

	tplFS, wfFS, useFS, err := CollectFilesystemTemplateSources(config)
	if err != nil {
		mc.outcome = "config_error"
		return nil, err
	}
	if useFS {
		mc.mode = "filesystem"
	} else {
		mc.mode = "database"
	}

	var opts []nucleilib.NucleiSDKOptions
	var templateCount int

	if useFS {
		templateCount = len(tplFS) + len(wfFS)
		slog.Info("[NucleiModule] 使用本地模板/工作流路径", append([]any{"template_paths", len(tplFS), "workflow_paths", len(wfFS)}, nucleiScanLogAttrs(config)...)...)
		opts = buildNucleiOptions(tplFS, wfFS, config)
	} else {
		templates := m.loadTemplates(config)
		if len(templates) == 0 && m.store.db != nil {
			if n, perr := tryPullPocFromMaster(ctx, m.store.db, config); perr != nil {
				slog.Warn("[NucleiModule] 从主控拉取 PoC 失败", append([]any{"error", perr}, nucleiScanLogAttrs(config)...)...)
			} else if n > 0 {
				slog.Info("[NucleiModule] 已从主控同步 PoC，重新加载模板", append([]any{"records", n}, nucleiScanLogAttrs(config)...)...)
				m.store.InvalidateCache()
				templates = m.loadTemplates(config)
			}
		}
		if len(templates) == 0 {
			if isVulnRetestConfig(config) {
				mc.outcome = "retest_no_templates"
				return nil, fmt.Errorf("回测未找到可用 PoC 模板")
			}
			slog.Info("[NucleiModule] 无PoC模板，跳过")
			mc.outcome = "skipped_no_templates"
			return &core.ModuleResult{Duration: time.Since(start)}, nil
		}

		templatePaths, matErr := materializePocTemplates(templates)
		if matErr != nil {
			mc.outcome = "init_error"
			return nil, matErr
		}
		if len(templatePaths) == 0 {
			slog.Info("[NucleiModule] 无有效模板路径，跳过")
			mc.outcome = "skipped_no_templates"
			return &core.ModuleResult{Duration: time.Since(start)}, nil
		}
		templateCount = len(templatePaths)
		opts = buildNucleiOptions(templatePaths, nil, config)
	}

	targetURLs := buildTargetURLs(targets)
	if len(targetURLs) == 0 {
		mc.outcome = "skipped_no_targets"
		return &core.ModuleResult{Duration: time.Since(start)}, nil
	}

	slog.Info("[NucleiModule] 开始Nuclei扫描", append([]any{"template_sources", templateCount, "targets", len(targetURLs)}, nucleiScanLogAttrs(config)...)...)

	var findings []*core.Finding
	var mu sync.Mutex

	ne, err := nucleilib.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		mc.outcome = "init_error"
		return nil, fmt.Errorf("初始化Nuclei引擎失败: %w", err)
	}
	defer ne.Close()

	ne.LoadTargets(targetURLs, true)

	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		finding := convertResultToFinding(event, targets)
		if finding != nil {
			mu.Lock()
			findings = append(findings, finding)
			mu.Unlock()
		}
	})
	if err != nil {
		slog.Warn("[NucleiModule] Nuclei执行出错", "error", err)
		mc.outcome = "execute_error"
	}
	mc.findings = len(findings)

	slog.Info("[NucleiModule] Nuclei扫描完成", append([]any{"findings", len(findings), "duration", time.Since(start).Round(time.Millisecond)}, nucleiScanLogAttrs(config)...)...)

	return &core.ModuleResult{
		Findings: findings,
		Duration: time.Since(start),
	}, nil
}

func isVulnRetestConfig(config map[string]interface{}) bool {
	return strings.TrimSpace(configString(config, "source_vuln_id", "")) != "" ||
		configString(config, "vuln_retest", "") == "true"
}

func (m *NucleiModule) loadTemplates(config map[string]interface{}) []*PocEntry {
	retest := isVulnRetestConfig(config)
	if ids := configStringSlice(config, "poc_template_ids"); len(ids) > 0 {
		matched := m.store.LoadByIDs(ids)
		if len(matched) > 0 {
			slog.Info("[NucleiModule] 按指定 PoC 回测", "templates", len(matched))
			return matched
		}
		if retest {
			slog.Warn("[NucleiModule] 回测指定 PoC 未在库中找到", "ids", ids)
			return nil
		}
		slog.Warn("[NucleiModule] 未找到指定 PoC 模板，回退全部 PoC", "ids", ids)
	}
	if retest {
		slog.Warn("[NucleiModule] 漏洞回测缺少 poc_template_ids，跳过全量 PoC")
		return nil
	}
	if severities, ok := config["poc_severities"].([]string); ok && len(severities) > 0 {
		return m.store.LoadBySeverity(severities)
	}
	if tags, ok := config["poc_tags"].([]string); ok && len(tags) > 0 {
		return m.store.LoadByTags(tags)
	}

	products := extractDetectedProducts(config)
	if len(products) > 0 {
		matched := m.store.LoadByProducts(products)
		if len(matched) > 0 {
			slog.Info("[NucleiModule] 基于指纹识别智能匹配PoC",
				"products", len(products), "matched_templates", len(matched))
			return matched
		}
		fallback := strings.ToLower(strings.TrimSpace(configString(config, "poc_unmatched_fallback", "skip")))
		if fallback == "all" {
			slog.Warn("[NucleiModule] 指纹匹配无结果，按配置回退为全部 PoC", "products", products)
			return m.store.LoadAll()
		}
		slog.Info("[NucleiModule] 指纹匹配无结果，跳过 nuclei（降低误报）；需要全量请设 poc_unmatched_fallback=all",
			"products", products)
		return nil
	}

	return m.store.LoadAll()
}

func extractDetectedProducts(config map[string]interface{}) []string {
	if products, ok := config["detected_products"].([]string); ok && len(products) > 0 {
		return products
	}
	if raw, ok := config["detected_products"].([]interface{}); ok && len(raw) > 0 {
		var products []string
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				products = append(products, s)
			}
		}
		return products
	}
	return nil
}

func buildNucleiOptions(templatePaths []string, workflowPaths []string, config map[string]interface{}) []nucleilib.NucleiSDKOptions {
	concurrency := nucleilib.Concurrency{
		TemplateConcurrency:           25,
		HostConcurrency:               10,
		HeadlessHostConcurrency:       2,
		HeadlessTemplateConcurrency:   2,
		JavascriptTemplateConcurrency: 15,
		TemplatePayloadConcurrency:    25,
		ProbeConcurrency:              50,
	}
	if hasDetectedWAFs(config) {
		concurrency.TemplateConcurrency = max(8, concurrency.TemplateConcurrency/2)
		concurrency.HostConcurrency = max(3, concurrency.HostConcurrency/2)
		concurrency.JavascriptTemplateConcurrency = max(5, concurrency.JavascriptTemplateConcurrency/2)
		slog.Info("[NucleiModule] 检测到 WAF，降低 nuclei 并发", "template_conc", concurrency.TemplateConcurrency, "host_conc", concurrency.HostConcurrency)
	}

	opts := []nucleilib.NucleiSDKOptions{
		nucleilib.WithTemplatesOrWorkflows(nucleilib.TemplateSources{
			Templates: templatePaths,
			Workflows: workflowPaths,
		}),
		nucleilib.DisableUpdateCheck(),
		nucleilib.WithNetworkConfig(nucleilib.NetworkConfig{
			Timeout:         15,
			Retries:         1,
			MaxHostError:    30,
			SystemResolvers: true,
		}),
		nucleilib.WithConcurrency(concurrency),
	}

	if rateLimit, ok := config["rate_limit"].(int); ok && rateLimit > 0 {
		opts = append(opts, nucleilib.WithGlobalRateLimit(rateLimit, time.Second))
	} else {
		opts = append(opts, nucleilib.WithGlobalRateLimit(100, time.Second))
	}

	if proxy, ok := config["proxy"].(string); ok && proxy != "" {
		opts = append(opts, nucleilib.WithProxy([]string{proxy}, false))
	}

	if headers, ok := config["headers"].([]string); ok && len(headers) > 0 {
		opts = append(opts, nucleilib.WithHeaders(headers))
	}

	headless := boolFromConfig(config, "nuclei_headless")
	if headless {
		pageTO := intFromConfig(config, "nuclei_headless_page_timeout", 25)
		if pageTO < 10 {
			pageTO = 10
		}
		opts = append(opts, nucleilib.EnableHeadlessWithOpts(&nucleilib.HeadlessOpts{
			PageTimeout:     pageTO,
			ShowBrowser:     false,
			UseChrome:       false,
			HeadlessOptions: nil,
		}))
	}

	if f := nucleiTemplateFilters(config, headless); f != nil {
		opts = append(opts, nucleilib.WithTemplateFilters(*f))
	}

	opts = mergeInteractshNucleiOptions(opts, config)

	if boolFromConfig(config, "nuclei_enable_stats") {
		interval := intFromConfig(config, "nuclei_stats_interval_seconds", 30)
		if interval < 5 {
			interval = 5
		}
		opts = append(opts, nucleilib.EnableStatsWithOpts(nucleilib.StatsOptions{
			Interval:         interval,
			JSON:             boolFromConfig(config, "nuclei_stats_json"),
			MetricServerPort: intFromConfig(config, "nuclei_stats_metrics_port", 0),
		}))
	}

	return opts
}

func nucleiTemplateFilters(config map[string]interface{}, headlessEnabled bool) *nucleilib.TemplateFilters {
	f := nucleilib.TemplateFilters{}

	if _, ok := config["nuclei_exclude_severities"]; ok {
		f.ExcludeSeverities = strings.TrimSpace(configString(config, "nuclei_exclude_severities", ""))
	} else {
		f.ExcludeSeverities = "info"
	}

	if sev := strings.TrimSpace(configString(config, "nuclei_severity", "")); sev != "" {
		f.Severity = sev
	}
	if tags := configStringSlice(config, "nuclei_tags"); len(tags) > 0 {
		f.Tags = tags
	}
	if inc := configStringSlice(config, "nuclei_include_tags"); len(inc) > 0 {
		f.IncludeTags = inc
	}
	if ex := configStringSlice(config, "nuclei_exclude_tags"); len(ex) > 0 {
		f.ExcludeTags = ex
	}
	if ids := configStringSlice(config, "nuclei_include_ids"); len(ids) > 0 {
		f.IDs = ids
	}
	if exIDs := configStringSlice(config, "nuclei_exclude_ids"); len(exIDs) > 0 {
		f.ExcludeIDs = exIDs
	}
	if p := strings.TrimSpace(configString(config, "nuclei_protocols", "")); p != "" {
		f.ProtocolTypes = p
	}
	if !headlessEnabled {
		prev := strings.TrimSpace(f.ExcludeProtocolTypes)
		if prev == "" {
			f.ExcludeProtocolTypes = "headless"
		} else if !strings.Contains(strings.ToLower(prev), "headless") {
			f.ExcludeProtocolTypes = prev + ",headless"
		}
	}
	if ep := strings.TrimSpace(configString(config, "nuclei_exclude_protocols", "")); ep != "" {
		if f.ExcludeProtocolTypes != "" {
			f.ExcludeProtocolTypes += ","
		}
		f.ExcludeProtocolTypes += ep
	}

	if f.Severity == "" && f.ExcludeSeverities == "" && len(f.Tags) == 0 && len(f.IncludeTags) == 0 &&
		len(f.ExcludeTags) == 0 && len(f.IDs) == 0 && len(f.ExcludeIDs) == 0 &&
		f.ProtocolTypes == "" && f.ExcludeProtocolTypes == "" {
		return nil
	}
	return &f
}

func hasDetectedWAFs(config map[string]interface{}) bool {
	if s, ok := config["detected_wafs"].([]string); ok && len(s) > 0 {
		return true
	}
	if raw, ok := config["detected_wafs"].([]interface{}); ok && len(raw) > 0 {
		return len(raw) > 0
	}
	return false
}

func configString(config map[string]interface{}, key, def string) string {
	v, ok := config[key]
	if !ok || v == nil {
		return def
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return def
}

func configStringSlice(config map[string]interface{}, key string) []string {
	v, ok := config[key]
	if !ok || v == nil {
		return nil
	}
	if ss, ok := v.([]string); ok {
		return ss
	}
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func boolFromConfig(config map[string]interface{}, key string) bool {
	v, ok := config[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

func intFromConfig(config map[string]interface{}, key string, def int) int {
	if config == nil {
		return def
	}
	v, ok := config[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(t), "%d", &n)
		return n
	default:
		return def
	}
}

func nucleiScanLogAttrs(config map[string]interface{}) []any {
	if config == nil {
		return nil
	}
	var a []any
	if tid := strings.TrimSpace(configString(config, "scan_task_id", "")); tid != "" {
		a = append(a, "scan_task_id", tid)
	}
	if pid := strings.TrimSpace(configString(config, "scan_parent_task_id", "")); pid != "" {
		a = append(a, "scan_parent_task_id", pid)
	}
	if rid := strings.TrimSpace(configString(config, "scan_request_id", "")); rid != "" {
		a = append(a, "scan_request_id", rid)
	}
	return a
}

func buildTargetURLs(targets []*core.Target) []string {
	var urls []string
	for _, t := range targets {
		url := targetToURL(t)
		if url != "" {
			urls = append(urls, url)
		}
	}
	return urls
}

func targetToURL(t *core.Target) string {
	if t.URL != "" {
		return t.URL
	}
	host := t.Host
	if host == "" {
		host = t.IP
	}
	if host == "" {
		return ""
	}
	if t.Port == 0 {
		return host
	}
	// 非 HTTP 服务端口：Nuclei network 模板需要 host:port，而非 http://host:port
	if isNucleiNetworkPort(t.Port) {
		return fmt.Sprintf("%s:%d", host, t.Port)
	}
	scheme := "http"
	if t.Port == 443 || t.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)
}

func isNucleiNetworkPort(port int) bool {
	switch port {
	case 21, 22, 23, 25, 110, 143, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017:
		return true
	default:
		return false
	}
}

func convertResultToFinding(event *output.ResultEvent, targets []*core.Target) *core.Finding {
	if event == nil {
		return nil
	}

	target := findMatchingTarget(event.Host, targets)
	if target == nil {
		target = &core.Target{
			Host: event.Host,
			IP:   event.IP,
			URL:  event.Matched,
		}
	}

	severity := "info"
	if event.Info.SeverityHolder.Severity.String() != "" {
		severity = event.Info.SeverityHolder.Severity.String()
	}

	evidence := buildEvidence(event)

	data := make(map[string]string)
	data["template_id"] = event.TemplateID
	data["matched_at"] = event.Matched
	if event.MatcherName != "" {
		data["matcher_name"] = event.MatcherName
	}
	if event.CURLCommand != "" {
		data["curl_command"] = event.CURLCommand
	}
	if event.Info.Classification != nil {
		if cveIDs := event.Info.Classification.CVEID.ToSlice(); len(cveIDs) > 0 {
			data["cve_id"] = cveIDs[0]
		}
		if cweIDs := event.Info.Classification.CWEID.ToSlice(); len(cweIDs) > 0 {
			data["cwe_id"] = cweIDs[0]
		}
		if event.Info.Classification.CVSSScore > 0 {
			data["cvss_score"] = fmt.Sprintf("%.1f", event.Info.Classification.CVSSScore)
		}
	}
	for _, extracted := range event.ExtractedResults {
		if len(data["extracted"]) == 0 {
			data["extracted"] = extracted
		} else {
			data["extracted"] += "; " + extracted
		}
	}

	return &core.Finding{
		ModuleID:    "nuclei-poc",
		Type:        "nuclei",
		Target:      target,
		Title:       event.Info.Name,
		Description: event.Info.Description,
		Severity:    severity,
		Confidence:  90,
		Evidence:    evidence,
		Data:        data,
		Timestamp:   event.Timestamp,
	}
}

func buildEvidence(event *output.ResultEvent) string {
	evidence := fmt.Sprintf("Template: %s\nMatched: %s\n", event.TemplateID, event.Matched)
	if event.Request != "" {
		req := event.Request
		if len(req) > 1000 {
			req = req[:1000] + "..."
		}
		evidence += "\n--- Request ---\n" + req
	}
	if event.Response != "" {
		resp := event.Response
		if len(resp) > 2000 {
			resp = resp[:2000] + "..."
		}
		evidence += "\n--- Response ---\n" + resp
	}
	return evidence
}

func findMatchingTarget(host string, targets []*core.Target) *core.Target {
	for _, t := range targets {
		if t.Host == host || t.IP == host || t.URL == host {
			return t
		}
	}
	return nil
}
