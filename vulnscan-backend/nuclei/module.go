package nuclei

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"gorm.io/gorm"

	"vulnscan-backend/scan/engine"
)

type NucleiModule struct {
	store    *PocStore
	mu       sync.Mutex
	cacheDir string
	cacheVer int64
}

func NewModule(db *gorm.DB) *NucleiModule {
	return &NucleiModule{
		store: NewPocStore(db),
	}
}

func NewModuleWithoutDB() *NucleiModule {
	return &NucleiModule{
		store: NewPocStoreNoDB(),
	}
}

func (m *NucleiModule) ID() string       { return "nuclei-poc" }
func (m *NucleiModule) Name() string     { return "Nuclei PoC Scanner" }
func (m *NucleiModule) Category() string { return "vuln" }

func (m *NucleiModule) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()

	templates := m.loadTemplates(config)
	if len(templates) == 0 {
		slog.Info("[NucleiModule] 无PoC模板，跳过")
		return &engine.ModuleResult{Duration: time.Since(start)}, nil
	}

	templateDir, err := m.ensureTemplateDir(templates)
	if err != nil {
		return nil, fmt.Errorf("准备模板目录失败: %w", err)
	}

	targetURLs := buildTargetURLs(targets)
	if len(targetURLs) == 0 {
		return &engine.ModuleResult{Duration: time.Since(start)}, nil
	}

	slog.Info("[NucleiModule] 开始Nuclei扫描", "templates", len(templates), "targets", len(targetURLs))

	var findings []*engine.Finding
	var mu sync.Mutex

	opts := buildNucleiOptions(templateDir, config)

	ne, err := nucleilib.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
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
	}

	slog.Info("[NucleiModule] Nuclei扫描完成", "findings", len(findings), "duration", time.Since(start).Round(time.Millisecond))

	return &engine.ModuleResult{
		Findings: findings,
		Duration: time.Since(start),
	}, nil
}

func (m *NucleiModule) loadTemplates(config map[string]interface{}) []*PocEntry {
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
		slog.Info("[NucleiModule] 指纹匹配无结果，使用全部PoC", "products", products)
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

func buildNucleiOptions(templateDir string, config map[string]interface{}) []nucleilib.NucleiSDKOptions {
	opts := []nucleilib.NucleiSDKOptions{
		nucleilib.WithTemplatesOrWorkflows(nucleilib.TemplateSources{
			Templates: []string{templateDir},
		}),
		nucleilib.DisableUpdateCheck(),
		nucleilib.WithNetworkConfig(nucleilib.NetworkConfig{
			Timeout:         15,
			Retries:         1,
			MaxHostError:    30,
			SystemResolvers: true,
		}),
		nucleilib.WithConcurrency(nucleilib.Concurrency{
			TemplateConcurrency: 25,
			HostConcurrency:     10,
		}),
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

	return opts
}

func buildTargetURLs(targets []*engine.Target) []string {
	var urls []string
	for _, t := range targets {
		url := targetToURL(t)
		if url != "" {
			urls = append(urls, url)
		}
	}
	return urls
}

func targetToURL(t *engine.Target) string {
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
	scheme := "http"
	if t.Port == 443 || t.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)
}

func convertResultToFinding(event *output.ResultEvent, targets []*engine.Target) *engine.Finding {
	if event == nil {
		return nil
	}

	target := findMatchingTarget(event.Host, targets)
	if target == nil {
		target = &engine.Target{
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

	return &engine.Finding{
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

func findMatchingTarget(host string, targets []*engine.Target) *engine.Target {
	for _, t := range targets {
		if t.Host == host || t.IP == host || t.URL == host {
			return t
		}
	}
	return nil
}

func (m *NucleiModule) ensureTemplateDir(templates []*PocEntry) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	currentVer := m.store.CacheVersion()
	if m.cacheDir != "" && m.cacheVer == currentVer {
		if _, err := os.Stat(m.cacheDir); err == nil {
			return m.cacheDir, nil
		}
	}

	if m.cacheDir != "" {
		os.RemoveAll(m.cacheDir)
	}

	dir, err := os.MkdirTemp("", "nuclei-templates-*")
	if err != nil {
		return "", err
	}

	for _, tmpl := range templates {
		fileName := sanitizeFileName(tmpl.ID) + ".yaml"
		path := filepath.Join(dir, fileName)
		if writeErr := os.WriteFile(path, []byte(tmpl.RawContent), 0644); writeErr != nil {
			slog.Warn("[NucleiModule] 写入模板失败", "id", tmpl.ID, "error", writeErr)
		}
	}

	m.cacheDir = dir
	m.cacheVer = currentVer
	return dir, nil
}

func sanitizeFileName(id string) string {
	result := make([]byte, 0, len(id))
	for _, c := range []byte(id) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}
