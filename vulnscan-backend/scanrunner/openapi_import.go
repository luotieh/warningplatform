package scanrunner

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"

	"code.yt-security.com/public/scanengine/core"

	"gopkg.in/yaml.v3"
)

// OpenAPIImporter parses OpenAPI/Swagger specs and converts them into scan targets.
type OpenAPIImporter struct{}

func NewOpenAPIImporter() *OpenAPIImporter {
	return &OpenAPIImporter{}
}

// APIEndpoint represents a discovered API endpoint.
type APIEndpoint struct {
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Summary     string          `json:"summary,omitempty"`
	OperationID string          `json:"operation_id,omitempty"`
	Parameters  []APIParameter  `json:"parameters,omitempty"`
	ContentType string          `json:"content_type,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Security    []string        `json:"security,omitempty"`
	RequestBody *APIRequestBody `json:"request_body,omitempty"`
}

type APIParameter struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Type     string `json:"type"`
	Example  string `json:"example,omitempty"`
}

type APIRequestBody struct {
	ContentType string                 `json:"content_type"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
	Example     interface{}            `json:"example,omitempty"`
}

// ImportResult contains the results of parsing an API specification.
type ImportResult struct {
	Title      string         `json:"title"`
	Version    string         `json:"version"`
	BaseURL    string         `json:"base_url"`
	Endpoints  []APIEndpoint  `json:"endpoints"`
	Targets    []*core.Target `json:"targets"`
	TotalPaths int            `json:"total_paths"`
	TotalOps   int            `json:"total_ops"`
}

// Parse accepts raw spec content (JSON or YAML) and returns discovered endpoints.
func (o *OpenAPIImporter) Parse(specContent []byte, baseURLOverride string) (*ImportResult, error) {
	var raw map[string]interface{}

	if err := json.Unmarshal(specContent, &raw); err != nil {
		if err2 := yaml.Unmarshal(specContent, &raw); err2 != nil {
			return nil, fmt.Errorf("无法解析规范文件（JSON: %v, YAML: %v）", err, err2)
		}
	}

	if swagger, ok := raw["swagger"].(string); ok && strings.HasPrefix(swagger, "2") {
		return o.parseSwagger2(raw, baseURLOverride)
	}

	if openapi, ok := raw["openapi"].(string); ok && strings.HasPrefix(openapi, "3") {
		return o.parseOpenAPI3(raw, baseURLOverride)
	}

	return nil, fmt.Errorf("不支持的 API 规范格式，需要 Swagger 2.x 或 OpenAPI 3.x")
}

func (o *OpenAPIImporter) parseSwagger2(raw map[string]interface{}, baseURLOverride string) (*ImportResult, error) {
	result := &ImportResult{}

	if info, ok := raw["info"].(map[string]interface{}); ok {
		result.Title, _ = info["title"].(string)
		result.Version, _ = info["version"].(string)
	}

	host, _ := raw["host"].(string)
	basePath, _ := raw["basePath"].(string)
	schemes := []string{"https"}
	if schemeList, ok := raw["schemes"].([]interface{}); ok {
		schemes = nil
		for _, s := range schemeList {
			if str, ok := s.(string); ok {
				schemes = append(schemes, str)
			}
		}
	}

	if baseURLOverride != "" {
		result.BaseURL = strings.TrimRight(baseURLOverride, "/")
	} else if host != "" {
		scheme := "https"
		if len(schemes) > 0 {
			scheme = schemes[0]
		}
		result.BaseURL = scheme + "://" + host + basePath
	}

	paths, ok := raw["paths"].(map[string]interface{})
	if !ok {
		return result, nil
	}

	result.TotalPaths = len(paths)

	for path, methods := range paths {
		methodMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		pathParams := extractSwagger2Parameters(methodMap, "")

		for method, opRaw := range methodMap {
			method = strings.ToUpper(method)
			if !isHTTPMethod(method) {
				continue
			}

			op, ok := opRaw.(map[string]interface{})
			if !ok {
				continue
			}

			endpoint := APIEndpoint{
				Method: method,
				Path:   path,
			}

			if summary, ok := op["summary"].(string); ok {
				endpoint.Summary = summary
			}
			if opID, ok := op["operationId"].(string); ok {
				endpoint.OperationID = opID
			}
			if tags, ok := op["tags"].([]interface{}); ok {
				for _, t := range tags {
					if s, ok := t.(string); ok {
						endpoint.Tags = append(endpoint.Tags, s)
					}
				}
			}

			params := extractSwagger2Parameters(op, "")
			params = append(pathParams, params...)
			endpoint.Parameters = params

			if consumes, ok := op["consumes"].([]interface{}); ok && len(consumes) > 0 {
				if s, ok := consumes[0].(string); ok {
					endpoint.ContentType = s
				}
			}

			result.Endpoints = append(result.Endpoints, endpoint)
			result.TotalOps++
		}
	}

	result.Targets = o.endpointsToTargets(result.Endpoints, result.BaseURL)

	slog.Info("[OpenAPIImport] Swagger 2.x 解析完成",
		"title", result.Title,
		"paths", result.TotalPaths,
		"operations", result.TotalOps,
		"targets", len(result.Targets))

	return result, nil
}

func (o *OpenAPIImporter) parseOpenAPI3(raw map[string]interface{}, baseURLOverride string) (*ImportResult, error) {
	result := &ImportResult{}

	if info, ok := raw["info"].(map[string]interface{}); ok {
		result.Title, _ = info["title"].(string)
		result.Version, _ = info["version"].(string)
	}

	if baseURLOverride != "" {
		result.BaseURL = strings.TrimRight(baseURLOverride, "/")
	} else if servers, ok := raw["servers"].([]interface{}); ok && len(servers) > 0 {
		if srv, ok := servers[0].(map[string]interface{}); ok {
			if srvURL, ok := srv["url"].(string); ok {
				result.BaseURL = strings.TrimRight(srvURL, "/")
			}
		}
	}

	paths, ok := raw["paths"].(map[string]interface{})
	if !ok {
		return result, nil
	}

	result.TotalPaths = len(paths)

	for path, methods := range paths {
		methodMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		for method, opRaw := range methodMap {
			method = strings.ToUpper(method)
			if !isHTTPMethod(method) {
				continue
			}

			op, ok := opRaw.(map[string]interface{})
			if !ok {
				continue
			}

			endpoint := APIEndpoint{
				Method: method,
				Path:   path,
			}

			if summary, ok := op["summary"].(string); ok {
				endpoint.Summary = summary
			}
			if opID, ok := op["operationId"].(string); ok {
				endpoint.OperationID = opID
			}
			if tags, ok := op["tags"].([]interface{}); ok {
				for _, t := range tags {
					if s, ok := t.(string); ok {
						endpoint.Tags = append(endpoint.Tags, s)
					}
				}
			}

			if params, ok := op["parameters"].([]interface{}); ok {
				for _, p := range params {
					if pm, ok := p.(map[string]interface{}); ok {
						endpoint.Parameters = append(endpoint.Parameters, extractOpenAPI3Param(pm))
					}
				}
			}

			if reqBody, ok := op["requestBody"].(map[string]interface{}); ok {
				endpoint.RequestBody = extractOpenAPI3RequestBody(reqBody)
			}

			if security, ok := op["security"].([]interface{}); ok {
				for _, s := range security {
					if sm, ok := s.(map[string]interface{}); ok {
						for name := range sm {
							endpoint.Security = append(endpoint.Security, name)
						}
					}
				}
			}

			result.Endpoints = append(result.Endpoints, endpoint)
			result.TotalOps++
		}
	}

	result.Targets = o.endpointsToTargets(result.Endpoints, result.BaseURL)

	slog.Info("[OpenAPIImport] OpenAPI 3.x 解析完成",
		"title", result.Title,
		"paths", result.TotalPaths,
		"operations", result.TotalOps,
		"targets", len(result.Targets))

	return result, nil
}

func (o *OpenAPIImporter) endpointsToTargets(endpoints []APIEndpoint, baseURL string) []*core.Target {
	if baseURL == "" {
		return nil
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path != endpoints[j].Path {
			return endpoints[i].Path < endpoints[j].Path
		}
		return endpoints[i].Method < endpoints[j].Method
	})

	var targets []*core.Target
	seen := make(map[string]bool)

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	for _, ep := range endpoints {
		fullPath := strings.TrimRight(parsedBase.Path, "/") + ep.Path
		fullURL := parsedBase.Scheme + "://" + parsedBase.Host + fullPath

		key := ep.Method + " " + fullURL
		if seen[key] {
			continue
		}
		seen[key] = true

		extra := map[string]string{
			"source":       "openapi",
			"method":       ep.Method,
			"path":         ep.Path,
			"operation_id": ep.OperationID,
		}
		if len(ep.Tags) > 0 {
			extra["tags"] = strings.Join(ep.Tags, ",")
		}
		if ep.Summary != "" {
			extra["summary"] = ep.Summary
		}
		if len(ep.Parameters) > 0 {
			paramNames := make([]string, 0, len(ep.Parameters))
			for _, p := range ep.Parameters {
				paramNames = append(paramNames, p.Name+"("+p.In+")")
			}
			extra["params"] = strings.Join(paramNames, ",")
		}
		if len(ep.Security) > 0 {
			extra["security"] = strings.Join(ep.Security, ",")
		}
		if ep.ContentType != "" {
			extra["content_type"] = ep.ContentType
		}

		t := &core.Target{
			Host:  parsedBase.Host,
			URL:   fullURL,
			Extra: extra,
		}

		port := parsedBase.Port()
		if port == "" {
			if parsedBase.Scheme == "https" {
				t.Port = 443
			} else {
				t.Port = 80
			}
		}

		targets = append(targets, t)
	}

	return targets
}

func extractSwagger2Parameters(obj map[string]interface{}, _ string) []APIParameter {
	var params []APIParameter

	rawParams, ok := obj["parameters"].([]interface{})
	if !ok {
		return params
	}

	for _, p := range rawParams {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}

		param := APIParameter{
			Name: getStrField(pm, "name"),
			In:   getStrField(pm, "in"),
		}
		if req, ok := pm["required"].(bool); ok {
			param.Required = req
		}
		if t, ok := pm["type"].(string); ok {
			param.Type = t
		}
		if ex, ok := pm["example"]; ok {
			param.Example = fmt.Sprintf("%v", ex)
		}

		params = append(params, param)
	}

	return params
}

func extractOpenAPI3Param(pm map[string]interface{}) APIParameter {
	param := APIParameter{
		Name: getStrField(pm, "name"),
		In:   getStrField(pm, "in"),
	}
	if req, ok := pm["required"].(bool); ok {
		param.Required = req
	}
	if schema, ok := pm["schema"].(map[string]interface{}); ok {
		if t, ok := schema["type"].(string); ok {
			param.Type = t
		}
		if ex, ok := schema["example"]; ok {
			param.Example = fmt.Sprintf("%v", ex)
		}
	}
	return param
}

func extractOpenAPI3RequestBody(reqBody map[string]interface{}) *APIRequestBody {
	content, ok := reqBody["content"].(map[string]interface{})
	if !ok {
		return nil
	}

	for ct, mediaRaw := range content {
		media, ok := mediaRaw.(map[string]interface{})
		if !ok {
			continue
		}
		rb := &APIRequestBody{
			ContentType: ct,
		}
		if schema, ok := media["schema"].(map[string]interface{}); ok {
			rb.Schema = schema
		}
		if example, ok := media["example"]; ok {
			rb.Example = example
		}
		return rb
	}

	return nil
}

func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	}
	return false
}

func getStrField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
