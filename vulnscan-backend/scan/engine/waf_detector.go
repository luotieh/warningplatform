package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type WAFDetector struct {
	client *http.Client
}

type WAFDetectionInfo struct {
	Name       string
	Type       string
	Confidence int
}

func NewWAFDetector() *WAFDetector {
	pool := GetGlobalClientPool()
	return &WAFDetector{
		client: pool.GetDefault().client,
	}
}

func (d *WAFDetector) Detect(ctx context.Context, target *Target) *WAFDetectionInfo {
	if target.URL == "" && target.Host != "" {
		target.URL = fmt.Sprintf("http://%s", target.Host)
		if target.Port == 443 || target.Protocol == "https" {
			target.URL = fmt.Sprintf("https://%s", target.Host)
		}
	}

	detectors := []func(context.Context, string) *WAFDetectionInfo{
		d.detectByHeader,
		d.detectByCookie,
		d.detectByResponseBody,
		d.detectByStatusCode,
		d.detectByProbe,
	}

	for _, detect := range detectors {
		if info := detect(ctx, target.URL); info != nil {
			slog.Info("[WAF-Detector] 检测到WAF/IPS",
				"target", target.URL,
				"waf_name", info.Name,
				"waf_type", info.Type,
				"confidence", info.Confidence,
			)
			return info
		}
	}

	return nil
}

func (d *WAFDetector) detectByHeader(ctx context.Context, url string) *WAFDetectionInfo {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	headerSignatures := map[string]map[string]string{
		"X-Sucuri-ID":      {"Name": "Sucuri", "Type": "WAF"},
		"X-CDN":            {"Name": "Generic CDN/WAF", "Type": "WAF"},
		"X-WAF-Protection": {"Name": "Generic WAF", "Type": "WAF"},
		"CF-RAY":           {"Name": "Cloudflare", "Type": "WAF/CDN"},
		"X-Powered-By":     {"Name": "Generic", "Type": "Info"},
	}

	for header, info := range headerSignatures {
		if resp.Header.Get(header) != "" {
			return &WAFDetectionInfo{
				Name:       info["Name"],
				Type:       info["Type"],
				Confidence: 90,
			}
		}
	}

	server := resp.Header.Get("Server")
	if strings.Contains(server, "cloudflare") {
		return &WAFDetectionInfo{Name: "Cloudflare", Type: "WAF/CDN", Confidence: 95}
	}
	if strings.Contains(server, "AkamaiGHost") {
		return &WAFDetectionInfo{Name: "Akamai", Type: "WAF/CDN", Confidence: 95}
	}
	if strings.Contains(server, "F5 BIG-IP") {
		return &WAFDetectionInfo{Name: "F5 BIG-IP", Type: "WAF", Confidence: 90}
	}

	return nil
}

func (d *WAFDetector) detectByCookie(ctx context.Context, url string) *WAFDetectionInfo {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	cookieSignatures := map[string]string{
		"__cfduid":     "Cloudflare",
		"sucuri":       "Sucuri",
		"citrix_ns_id": "Citrix NetScaler",
		"TS":           "F5 BIG-IP",
		"ASPSESSION":   "ASP.NET WAF",
	}

	for _, cookie := range resp.Cookies() {
		for pattern, name := range cookieSignatures {
			if strings.Contains(strings.ToLower(cookie.Name), pattern) {
				return &WAFDetectionInfo{Name: name, Type: "WAF", Confidence: 85}
			}
		}
	}

	return nil
}

func (d *WAFDetector) detectByResponseBody(ctx context.Context, url string) *WAFDetectionInfo {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body := make([]byte, 8192)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	bodySignatures := map[string]string{
		"Access Denied":            "Generic WAF",
		"Request Blocked":          "Generic WAF",
		"Security Violation":       "Generic WAF",
		"Protected by ModSecurity": "ModSecurity",
		"ModSecurity":              "ModSecurity",
		"SUCURI":                   "Sucuri",
		"Cloudflare Ray ID":        "Cloudflare",
		"Web Application Firewall": "Generic WAF",
	}

	for pattern, name := range bodySignatures {
		if strings.Contains(bodyStr, pattern) {
			return &WAFDetectionInfo{Name: name, Type: "WAF", Confidence: 80}
		}
	}

	return nil
}

func (d *WAFDetector) detectByStatusCode(ctx context.Context, url string) *WAFDetectionInfo {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+"/nonexistent_path_404_test", nil)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 503 {
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])

		if strings.Contains(bodyStr, "blocked") ||
			strings.Contains(bodyStr, "forbidden") ||
			strings.Contains(bodyStr, "security") {
			return &WAFDetectionInfo{Name: "Generic WAF/IPS", Type: "WAF", Confidence: 60}
		}
	}

	return nil
}

func (d *WAFDetector) detectByProbe(ctx context.Context, url string) *WAFDetectionInfo {
	probePayloads := []string{
		"<script>alert(1)</script>",
		"' OR 1=1--",
		"../../etc/passwd",
	}

	for _, payload := range probePayloads {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+"?test="+payload, nil)
		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 419 {
			return &WAFDetectionInfo{Name: "Generic WAF/IPS", Type: "WAF", Confidence: 75}
		}

		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])

		if strings.Contains(bodyStr, "blocked") ||
			strings.Contains(bodyStr, "detected") ||
			strings.Contains(bodyStr, "attack") {
			return &WAFDetectionInfo{Name: "Generic WAF/IPS", Type: "WAF", Confidence: 70}
		}
	}

	return nil
}

type WAFDetectorModule struct {
	detector *WAFDetector
}

func NewWAFDetectorModule() *WAFDetectorModule {
	return &WAFDetectorModule{
		detector: NewWAFDetector(),
	}
}

func (m *WAFDetectorModule) ID() string       { return "waf-detector" }
func (m *WAFDetectorModule) Name() string     { return "WAF/IPS Detector" }
func (m *WAFDetectorModule) Category() string { return "recon" }

func (m *WAFDetectorModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	var findings []*Finding

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return &ModuleResult{
				ModuleID: m.ID(),
				Findings: findings,
				Duration: time.Since(start),
			}, ctx.Err()
		default:
		}

		wafInfo := m.detector.Detect(ctx, target)
		if wafInfo != nil {
			findings = append(findings, &Finding{
				Target:     target,
				Type:       "waf_detected",
				Title:      fmt.Sprintf("WAF/IPS Detected: %s", wafInfo.Name),
				Severity:   "info",
				Confidence: wafInfo.Confidence,
				Evidence:   fmt.Sprintf("WAF Name: %s, Type: %s", wafInfo.Name, wafInfo.Type),
				Timestamp:  time.Now(),
				Data: map[string]string{
					"waf_name":   wafInfo.Name,
					"waf_type":   wafInfo.Type,
					"confidence": fmt.Sprintf("%d", wafInfo.Confidence),
				},
			})

			target.WAFDetected = true
			target.WAFName = wafInfo.Name
		}
	}

	slog.Info("[WAF-Detector] 检测完成",
		"targets", len(targets),
		"waf_found", len(findings),
		"duration", time.Since(start),
	)

	return &ModuleResult{
		ModuleID: m.ID(),
		Findings: findings,
		Duration: time.Since(start),
	}, nil
}
