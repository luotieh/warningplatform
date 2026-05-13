package vulnkit

import (
	"vulnscan-backend/scan/core"

	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type InjectionPointType string

const (
	InjectQuery  InjectionPointType = "query"
	InjectBody   InjectionPointType = "body"
	InjectJSON   InjectionPointType = "json"
	InjectHeader InjectionPointType = "header"
	InjectCookie InjectionPointType = "cookie"
)

type InjectionPoint struct {
	Type     InjectionPointType
	Name     string
	Original string
}

type InjectionResult struct {
	Point   InjectionPoint
	Request *http.Request
	URL     string
}

func ExtractInjectionPoints(target *core.Target) []InjectionPoint {
	var points []InjectionPoint

	if target.URL == "" {
		return nil
	}

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	for name, vals := range parsed.Query() {
		orig := ""
		if len(vals) > 0 {
			orig = vals[0]
		}
		points = append(points, InjectionPoint{
			Type:     InjectQuery,
			Name:     name,
			Original: orig,
		})
	}

	if target.Extra != nil {
		if body, ok := target.Extra["request_body"]; ok && body != "" {
			ct := target.Extra["content_type"]

			if strings.Contains(ct, "json") || (strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")) {
				var obj map[string]interface{}
				if json.Unmarshal([]byte(body), &obj) == nil {
					for key, val := range obj {
						orig := ""
						if s, ok := val.(string); ok {
							orig = s
						}
						points = append(points, InjectionPoint{
							Type:     InjectJSON,
							Name:     key,
							Original: orig,
						})
					}
				}
			} else if strings.Contains(ct, "form") {
				formVals, err := url.ParseQuery(body)
				if err == nil {
					for name, vals := range formVals {
						orig := ""
						if len(vals) > 0 {
							orig = vals[0]
						}
						points = append(points, InjectionPoint{
							Type:     InjectBody,
							Name:     name,
							Original: orig,
						})
					}
				}
			}
		}
	}

	return points
}

func BuildInjectedRequest(ctx context.Context, target *core.Target, point InjectionPoint, payload string) (*http.Request, error) {
	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}

	method := "GET"
	if target.Extra != nil {
		if m, ok := target.Extra["method"]; ok && m != "" {
			method = strings.ToUpper(m)
		}
	}

	var body io.Reader

	switch point.Type {
	case InjectQuery:
		q := parsed.Query()
		q.Set(point.Name, payload)
		parsed.RawQuery = q.Encode()

	case InjectBody:
		formData := ""
		if target.Extra != nil {
			formData = target.Extra["request_body"]
		}
		vals, _ := url.ParseQuery(formData)
		vals.Set(point.Name, payload)
		body = strings.NewReader(vals.Encode())
		if method == "GET" {
			method = "POST"
		}

	case InjectJSON:
		rawBody := ""
		if target.Extra != nil {
			rawBody = target.Extra["request_body"]
		}
		var obj map[string]interface{}
		if rawBody != "" {
			json.Unmarshal([]byte(rawBody), &obj)
		}
		if obj == nil {
			obj = make(map[string]interface{})
		}
		obj[point.Name] = payload
		jsonBytes, _ := json.Marshal(obj)
		body = bytes.NewReader(jsonBytes)
		if method == "GET" {
			method = "POST"
		}

	case InjectHeader, InjectCookie:
		// handled after request creation
	}

	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return nil, err
	}

	switch point.Type {
	case InjectBody:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case InjectJSON:
		req.Header.Set("Content-Type", "application/json")
	case InjectHeader:
		req.Header.Set(point.Name, payload)
	case InjectCookie:
		req.AddCookie(&http.Cookie{Name: point.Name, Value: payload})
	}

	return req, nil
}

func InjectQueryParam(u *url.URL, param, payload string) string {
	q := u.Query()
	q.Set(param, payload)
	u2 := *u
	u2.RawQuery = q.Encode()
	return u2.String()
}

func AppendQueryParam(u *url.URL, param, payload string) string {
	q := u.Query()
	q.Set(param, q.Get(param)+payload)
	u2 := *u
	u2.RawQuery = q.Encode()
	return u2.String()
}

func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
