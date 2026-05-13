package apisec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/scanhttp"
	"vulnscan-backend/scan/vulnkit"
)

type APISecScanner struct {
	base *vulnkit.VulnScanner
}

func New() *APISecScanner {
	return &APISecScanner{}
}

func (m *APISecScanner) ID() string       { return "apisec" }
func (m *APISecScanner) Name() string     { return "API安全检测" }
func (m *APISecScanner) Category() string { return "vuln" }

var commonAPIPaths = []string{
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/graphql", "/graphiql", "/playground",
	"/swagger.json", "/swagger/v1/swagger.json",
	"/openapi.json", "/api-docs",
	"/swagger-ui.html", "/swagger-ui/",
	"/redoc", "/docs",
	"/.well-known/openapi.yaml",
	"/api/health", "/api/status", "/api/info",
	"/api/config", "/api/debug", "/api/metrics",
	"/api/env", "/api/version",
	"/actuator", "/actuator/env", "/actuator/health",
	"/actuator/info", "/actuator/beans", "/actuator/mappings",
	"/wp-json/wp/v2/users",
	"/_cat/indices", "/_cluster/health",
}

var sensitiveEndpoints = []struct {
	path      string
	indicator string
	severity  string
	detail    string
}{
	{"/api/users", "email", "medium", "用户列表可能暴露"},
	{"/api/admin", "", "high", "管理员接口未授权"},
	{"/api/config", "password", "critical", "配置接口暴露密码"},
	{"/api/debug", "stack", "high", "调试接口暴露"},
	{"/api/env", "DATABASE", "critical", "环境变量暴露"},
	{"/actuator/env", "spring", "critical", "Spring Actuator env暴露"},
	{"/actuator/mappings", "handler", "high", "Spring路由映射暴露"},
	{"/graphql", "data", "info", "GraphQL端点可访问"},
	{"/swagger.json", "paths", "medium", "Swagger文档暴露"},
	{"/_cat/indices", "health", "critical", "Elasticsearch未授权"},
}

func (m *APISecScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	m.base = vulnkit.NewVulnScanner(config, scanhttp.WithRedirectPolicy(scanhttp.RedirectNoFollow))

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *core.Target) []*core.Finding {
		baseURL := buildBaseURL(target)
		if baseURL == "" {
			return nil
		}
		return m.testTarget(ctx, target, baseURL)
	})

	vulnkit.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *APISecScanner) testTarget(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	var findings []*core.Finding

	findings = append(findings, m.discoverEndpoints(ctx, target, baseURL)...)
	findings = append(findings, m.testUnauthAccess(ctx, target, baseURL)...)
	findings = append(findings, m.testRateLimit(ctx, target, baseURL)...)
	findings = append(findings, m.testInfoLeak(ctx, target, baseURL)...)
	findings = append(findings, m.testIDOR(ctx, target, baseURL)...)
	findings = append(findings, m.testGraphQL(ctx, target, baseURL)...)

	return findings
}

func (m *APISecScanner) discoverEndpoints(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	var findings []*core.Finding

	for _, path := range commonAPIPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(baseURL, "/") + path
		resp, body := m.base.FetchFullResponse(ctx, fullURL)
		if resp == nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			for _, ep := range sensitiveEndpoints {
				if path == ep.path && (ep.indicator == "" || strings.Contains(strings.ToLower(body), ep.indicator)) {
					findings = append(findings, &core.Finding{
						ModuleID:    m.ID(),
						Target:      target,
						Type:        "api_endpoint_exposed",
						Title:       fmt.Sprintf("API端点暴露: %s", path),
						Description: ep.detail,
						Severity:    ep.severity,
						Confidence:  75,
						Evidence:    vulnkit.Truncate(body, 500),
						Timestamp:   time.Now(),
						Data: map[string]string{
							"path":   path,
							"url":    fullURL,
							"status": fmt.Sprintf("%d", resp.StatusCode),
						},
					})
				}
			}
		}
	}

	return findings
}

func (m *APISecScanner) testUnauthAccess(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	var findings []*core.Finding

	adminPaths := []string{
		"/api/admin/users", "/api/admin/settings",
		"/api/users", "/api/roles",
		"/admin/api/config",
	}

	for _, path := range adminPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(baseURL, "/") + path
		body, status := m.base.FetchWithStatus(ctx, fullURL)

		if status == 200 && len(body) > 50 {
			isJSON := strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[")
			if isJSON {
				findings = append(findings, &core.Finding{
					ModuleID:    m.ID(),
					Target:      target,
					Type:        "api_unauth_access",
					Title:       fmt.Sprintf("未授权API访问: %s", path),
					Description: fmt.Sprintf("无需认证即可访问管理接口 %s，返回JSON数据", path),
					Severity:    "high",
					Confidence:  70,
					Evidence:    vulnkit.Truncate(body, 500),
					Timestamp:   time.Now(),
					Data: map[string]string{
						"path":     path,
						"url":      fullURL,
						"body_len": fmt.Sprintf("%d", len(body)),
					},
				})
			}
		}
	}

	return findings
}

func (m *APISecScanner) testRateLimit(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	testURL := strings.TrimRight(baseURL, "/") + "/api/v1/login"
	_, status := m.base.FetchWithStatus(ctx, testURL)
	if status == 404 || status == 0 {
		testURL = strings.TrimRight(baseURL, "/") + "/api/auth/login"
		_, status = m.base.FetchWithStatus(ctx, testURL)
	}
	if status == 404 || status == 0 {
		return nil
	}

	successCount := 0
	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		resp, _ := m.base.SendRequest(ctx, "POST", testURL, `{"username":"test","password":"test"}`, map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		})
		if resp != nil && resp.StatusCode != 429 {
			successCount++
		}
		if resp != nil && resp.StatusCode == 429 {
			return nil
		}
	}

	if successCount >= 18 {
		return []*core.Finding{{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "api_no_rate_limit",
			Title:       "API缺少速率限制",
			Description: fmt.Sprintf("登录接口 %s 连续20次请求未触发429限流", testURL),
			Severity:    "medium",
			Confidence:  65,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"url":      testURL,
				"requests": "20",
				"passed":   fmt.Sprintf("%d", successCount),
			},
		}}
	}

	return nil
}

func (m *APISecScanner) testInfoLeak(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	var findings []*core.Finding

	resp, _ := m.base.FetchFullResponse(ctx, baseURL)
	if resp == nil {
		return nil
	}

	leaks := []struct {
		header   string
		severity string
	}{
		{"X-Powered-By", "low"},
		{"Server", "info"},
		{"X-AspNet-Version", "low"},
		{"X-AspNetMvc-Version", "low"},
	}

	for _, leak := range leaks {
		if val := resp.Header.Get(leak.header); val != "" {
			findings = append(findings, &core.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "api_info_leak_header",
				Title:       fmt.Sprintf("信息泄露: %s: %s", leak.header, val),
				Description: fmt.Sprintf("HTTP响应头 %s 暴露了服务器技术信息", leak.header),
				Severity:    leak.severity,
				Confidence:  90,
				Timestamp:   time.Now(),
				Data: map[string]string{
					"header": leak.header,
					"value":  val,
				},
			})
		}
	}

	corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if corsOrigin == "*" {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "api_cors_wildcard",
			Title:       "CORS配置过于宽松: Access-Control-Allow-Origin: *",
			Description: "CORS允许所有来源访问，可能导致跨域数据窃取",
			Severity:    "medium",
			Confidence:  85,
			Timestamp:   time.Now(),
		})
	}

	errorURLs := []string{
		baseURL + "/api/nonexistent999",
		baseURL + "/api/v1/../../../etc/passwd",
	}

	for _, u := range errorURLs {
		errBody := m.base.FetchBody(ctx, u)
		if strings.Contains(errBody, "stack") || strings.Contains(errBody, "traceback") ||
			strings.Contains(errBody, "at ") || strings.Contains(errBody, "Exception") {
			findings = append(findings, &core.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "api_verbose_error",
				Title:       "API错误信息过于详细",
				Description: "错误响应中包含堆栈跟踪或异常信息",
				Severity:    "medium",
				Confidence:  70,
				Evidence:    vulnkit.Truncate(errBody, 500),
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings
}

func (m *APISecScanner) testIDOR(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	var findings []*core.Finding

	idorPaths := []string{
		"/api/users/%s",
		"/api/v1/users/%s",
		"/api/orders/%s",
		"/api/profile/%s",
	}

	testIDs := []string{"1", "2", "admin", "0"}

	for _, pathTpl := range idorPaths {
		results := make(map[string]int)
		for _, id := range testIDs {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			fullURL := strings.TrimRight(baseURL, "/") + fmt.Sprintf(pathTpl, id)
			_, status := m.base.FetchWithStatus(ctx, fullURL)
			results[id] = status
		}

		successCount := 0
		for _, code := range results {
			if code == 200 {
				successCount++
			}
		}

		if successCount >= 2 {
			findings = append(findings, &core.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "api_idor",
				Title:       fmt.Sprintf("疑似IDOR: %s", fmt.Sprintf(pathTpl, "{id}")),
				Description: fmt.Sprintf("通过遍历ID(%v)可访问不同用户资源，%d/%d返回200", testIDs, successCount, len(testIDs)),
				Severity:    "high",
				Confidence:  55,
				Timestamp:   time.Now(),
				Data: map[string]string{
					"path":     fmt.Sprintf(pathTpl, "{id}"),
					"test_ids": strings.Join(testIDs, ","),
				},
			})
		}
	}

	return findings
}

func (m *APISecScanner) testGraphQL(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	var findings []*core.Finding

	gqlURL := strings.TrimRight(baseURL, "/") + "/graphql"
	introspection := `{"query":"{ __schema { types { name } } }"}`
	body, status := m.base.SendJSON(ctx, gqlURL, introspection)

	if status == 200 && strings.Contains(body, "__schema") {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "api_graphql_introspection",
			Title:       "GraphQL内省查询已启用",
			Description: "GraphQL端点允许内省查询(__schema)，攻击者可获取完整API模式",
			Severity:    "medium",
			Confidence:  90,
			Evidence:    vulnkit.Truncate(body, 500),
			Timestamp:   time.Now(),
			Data: map[string]string{
				"url": gqlURL,
			},
		})

		var result map[string]interface{}
		if json.Unmarshal([]byte(body), &result) == nil {
			if data, ok := result["data"].(map[string]interface{}); ok {
				if schema, ok := data["__schema"].(map[string]interface{}); ok {
					if types, ok := schema["types"].([]interface{}); ok {
						typeNames := make([]string, 0, len(types))
						for _, t := range types {
							if tm, ok := t.(map[string]interface{}); ok {
								if name, ok := tm["name"].(string); ok && !strings.HasPrefix(name, "__") {
									typeNames = append(typeNames, name)
								}
							}
						}
						if len(typeNames) > 0 {
							findings = append(findings, &core.Finding{
								ModuleID:    m.ID(),
								Target:      target,
								Type:        "api_graphql_types",
								Title:       fmt.Sprintf("GraphQL暴露 %d 个自定义类型", len(typeNames)),
								Description: fmt.Sprintf("类型列表: %s", strings.Join(typeNames, ", ")),
								Severity:    "info",
								Confidence:  95,
								Timestamp:   time.Now(),
							})
						}
					}
				}
			}
		}
	}

	return findings
}

func buildBaseURL(t *core.Target) string {
	if t.URL != "" {
		return t.URL
	}
	if t.Port <= 0 {
		return ""
	}
	host := t.Host
	if host == "" {
		host = t.IP
	}
	if host == "" {
		return ""
	}
	scheme := "http"
	if t.Port == 443 || t.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)
}
