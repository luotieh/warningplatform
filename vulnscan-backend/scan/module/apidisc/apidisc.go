package apidisc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type APIDiscovery struct {
	client *http.Client
}

func New() *APIDiscovery {
	return &APIDiscovery{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 5,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (m *APIDiscovery) ID() string       { return "api_disc" }
func (m *APIDiscovery) Name() string     { return "API 接口发现" }
func (m *APIDiscovery) Category() string { return "recon" }

var apiPaths = []struct {
	path    string
	apiType string
	detect  func(body string, status int) bool
}{
	// Swagger/OpenAPI
	{"/swagger.json", "swagger", detectJSON},
	{"/swagger/v1/swagger.json", "swagger", detectJSON},
	{"/api-docs", "swagger", detectSwaggerUI},
	{"/swagger-ui.html", "swagger", detectSwaggerUI},
	{"/swagger-ui/index.html", "swagger", detectSwaggerUI},
	{"/v2/api-docs", "swagger", detectJSON},
	{"/v3/api-docs", "swagger", detectJSON},
	{"/openapi.json", "openapi", detectJSON},
	{"/openapi.yaml", "openapi", detectYAML},
	{"/api/openapi.json", "openapi", detectJSON},
	{"/docs", "swagger", detectSwaggerUI},
	{"/redoc", "swagger", detectRedoc},
	{"/api/docs", "swagger", detectSwaggerUI},

	// GraphQL
	{"/graphql", "graphql", detectGraphQL},
	{"/graphiql", "graphql", detectGraphiQL},
	{"/api/graphql", "graphql", detectGraphQL},
	{"/v1/graphql", "graphql", detectGraphQL},
	{"/playground", "graphql", detectGraphiQL},

	// API Versioning
	{"/api/v1", "rest", detectAPI},
	{"/api/v2", "rest", detectAPI},
	{"/api/v3", "rest", detectAPI},

	// Health/Info
	{"/health", "health", detectHealth},
	{"/healthz", "health", detectHealth},
	{"/actuator", "spring_actuator", detectActuator},
	{"/actuator/health", "spring_actuator", detectHealth},
	{"/actuator/info", "spring_actuator", detectJSON},
	{"/actuator/env", "spring_actuator", detectJSON},
	{"/actuator/beans", "spring_actuator", detectJSON},
	{"/actuator/mappings", "spring_actuator", detectJSON},
	{"/.well-known/openid-configuration", "oidc", detectJSON},
	{"/debug/vars", "go_debug", detectJSON},
	{"/debug/pprof/", "go_debug", func(body string, status int) bool {
		return status == 200 && strings.Contains(body, "pprof")
	}},
}

func (m *APIDiscovery) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, t := range targets {
		baseURL := buildBaseURL(t)
		if baseURL == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *core.Target, base string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, ap := range apiPaths {
				select {
				case <-ctx.Done():
					return
				default:
				}

				testURL := base + ap.path
				status, body := m.probe(ctx, testURL)
				if status <= 0 {
					continue
				}

				if ap.detect(body, status) {
					severity := "info"
					if ap.apiType == "spring_actuator" || ap.apiType == "go_debug" {
						severity = "medium"
					}

					mu.Lock()
					result.Findings = append(result.Findings, &core.Finding{
						ModuleID:   m.ID(),
						Target:     target,
						Type:       "api_endpoint",
						Title:      fmt.Sprintf("[%s] %s", ap.apiType, ap.path),
						Severity:   severity,
						Confidence: 90,
						Timestamp:  time.Now(),
						Data: map[string]string{
							"url":      testURL,
							"api_type": ap.apiType,
							"status":   fmt.Sprintf("%d", status),
							"size":     fmt.Sprintf("%d", len(body)),
						},
					})
					mu.Unlock()
				}
			}
		}(t, baseURL)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	slog.Info("[+] API接口发现完成", "targets", len(targets), "findings", len(result.Findings), "duration", result.Duration)
	return result, nil
}

func (m *APIDiscovery) probe(ctx context.Context, rawURL string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, string(body)
}

func detectJSON(body string, status int) bool {
	return status == 200 && len(body) > 2 && (body[0] == '{' || body[0] == '[')
}

func detectYAML(body string, status int) bool {
	return status == 200 && (strings.Contains(body, "openapi:") || strings.Contains(body, "swagger:"))
}

func detectSwaggerUI(body string, status int) bool {
	return status == 200 && (strings.Contains(body, "swagger") || strings.Contains(body, "Swagger"))
}

func detectRedoc(body string, status int) bool {
	return status == 200 && strings.Contains(body, "redoc")
}

func detectGraphQL(body string, status int) bool {
	return status == 200 || status == 400 || (status == 405 && strings.Contains(body, "graphql"))
}

func detectGraphiQL(body string, status int) bool {
	return status == 200 && (strings.Contains(body, "graphiql") || strings.Contains(body, "GraphiQL") || strings.Contains(body, "playground"))
}

func detectAPI(body string, status int) bool {
	return status == 200 && len(body) > 2
}

func detectHealth(body string, status int) bool {
	return status == 200 && (strings.Contains(body, "UP") || strings.Contains(body, "ok") || strings.Contains(body, "healthy") || strings.Contains(body, "status"))
}

func detectActuator(body string, status int) bool {
	return status == 200 && strings.Contains(body, "_links")
}

func buildBaseURL(t *core.Target) string {
	if t.URL != "" {
		return strings.TrimRight(t.URL, "/")
	}
	if t.Port <= 0 {
		return ""
	}
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	scheme := "http"
	if t.Port == 443 || t.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)
}
