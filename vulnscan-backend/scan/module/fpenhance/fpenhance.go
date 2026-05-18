package fpenhance

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type FPEnhanceScanner struct {
	client *http.Client
}

func New() *FPEnhanceScanner {
	return &FPEnhanceScanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}
}

func (m *FPEnhanceScanner) ID() string       { return "fpenhance" }
func (m *FPEnhanceScanner) Name() string     { return "增强指纹探测" }
func (m *FPEnhanceScanner) Category() string { return "recon" }

func (m *FPEnhanceScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	concurrency := core.GetConfigInt(config, "concurrency", 8)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(target *core.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := m.analyzeTarget(ctx, target)
			mu.Lock()
			result.Findings = append(result.Findings, findings...)
			mu.Unlock()
		}(t)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 增强指纹探测完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)
	return result, nil
}

func (m *FPEnhanceScanner) analyzeTarget(ctx context.Context, target *core.Target) []*core.Finding {
	var findings []*core.Finding

	baseURL := buildBaseURL(target)
	if baseURL == "" {
		return nil
	}

	findings = append(findings, m.tlsFingerprint(ctx, target)...)
	findings = append(findings, m.headerFingerprint(ctx, target, baseURL)...)
	findings = append(findings, m.wafDetect(ctx, target, baseURL)...)
	findings = append(findings, m.jsFingerprint(ctx, target, baseURL)...)

	return findings
}

func (m *FPEnhanceScanner) tlsFingerprint(ctx context.Context, target *core.Target) []*core.Finding {
	if target.Port != 443 && target.Port != 8443 && target.Port != 4443 {
		return nil
	}

	host := target.Host
	if host == "" {
		host = target.IP
	}
	addr := fmt.Sprintf("%s:%d", host, target.Port)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]

	tlsVersions := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	tlsVersion := tlsVersions[state.Version]
	if tlsVersion == "" {
		tlsVersion = fmt.Sprintf("Unknown(0x%04x)", state.Version)
	}

	sans := cert.DNSNames
	issuer := cert.Issuer.CommonName
	subject := cert.Subject.CommonName

	fingerprint := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fingerprint[:])

	var findings []*core.Finding

	findings = append(findings, &core.Finding{
		ModuleID:    m.ID(),
		Target:      target,
		Type:        "tls_fingerprint",
		Title:       fmt.Sprintf("TLS证书指纹: %s (%s)", subject, tlsVersion),
		Description: fmt.Sprintf("Issuer: %s | SANs: %s | SHA256: %s", issuer, strings.Join(sans, ", "), fpHex[:16]),
		Severity:    "info",
		Confidence:  95,
		Timestamp:   time.Now(),
		Data: map[string]string{
			"subject":     subject,
			"issuer":      issuer,
			"sans":        strings.Join(sans, ","),
			"tls_version": tlsVersion,
			"sha256":      fpHex,
			"not_before":  cert.NotBefore.Format(time.RFC3339),
			"not_after":   cert.NotAfter.Format(time.RFC3339),
		},
	})

	if cert.NotAfter.Before(time.Now()) {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "tls_cert_expired",
			Title:       "TLS证书已过期",
			Description: fmt.Sprintf("证书 %s 已于 %s 过期", subject, cert.NotAfter.Format("2006-01-02")),
			Severity:    "medium",
			Confidence:  95,
			Timestamp:   time.Now(),
		})
	}

	if state.Version < tls.VersionTLS12 {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "tls_weak_version",
			Title:       fmt.Sprintf("使用弱TLS版本: %s", tlsVersion),
			Description: "建议升级到 TLS 1.2 或更高版本",
			Severity:    "medium",
			Confidence:  90,
			Timestamp:   time.Now(),
		})
	}

	return findings
}

func (m *FPEnhanceScanner) headerFingerprint(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	resp, _ := m.sendRequest(ctx, baseURL)
	if resp == nil {
		return nil
	}

	var findings []*core.Finding

	headerKeys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)

	headerHash := sha256.New()
	for _, k := range headerKeys {
		headerHash.Write([]byte(k))
	}
	headerFP := hex.EncodeToString(headerHash.Sum(nil))[:16]

	techHints := make(map[string]string)
	if v := resp.Header.Get("Server"); v != "" {
		techHints["server"] = v
	}
	if v := resp.Header.Get("X-Powered-By"); v != "" {
		techHints["powered_by"] = v
	}
	if v := resp.Header.Get("X-Generator"); v != "" {
		techHints["generator"] = v
	}
	if v := resp.Header.Get("X-AspNet-Version"); v != "" {
		techHints["aspnet"] = v
	}

	data := map[string]string{
		"header_fingerprint": headerFP,
		"header_count":       fmt.Sprintf("%d", len(headerKeys)),
		"headers":            strings.Join(headerKeys, ","),
	}
	for k, v := range techHints {
		data[k] = v
	}

	findings = append(findings, &core.Finding{
		ModuleID:    m.ID(),
		Target:      target,
		Type:        "header_fingerprint",
		Title:       fmt.Sprintf("HTTP头指纹: %s (%d headers)", headerFP, len(headerKeys)),
		Description: fmt.Sprintf("Server: %s | Headers: %s", techHints["server"], strings.Join(headerKeys, ", ")),
		Severity:    "info",
		Confidence:  85,
		Timestamp:   time.Now(),
		Data:        data,
	})

	secHeaders := map[string]string{
		"Strict-Transport-Security": "HSTS",
		"Content-Security-Policy":   "CSP",
		"X-Content-Type-Options":    "X-Content-Type-Options",
		"X-Frame-Options":           "X-Frame-Options",
		"X-XSS-Protection":          "X-XSS-Protection",
	}

	var missing []string
	for header, name := range secHeaders {
		if resp.Header.Get(header) == "" {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "missing_security_headers",
			Title:       fmt.Sprintf("缺少 %d 个安全响应头", len(missing)),
			Description: fmt.Sprintf("缺失: %s", strings.Join(missing, ", ")),
			Severity:    "low",
			Confidence:  90,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"missing": strings.Join(missing, ","),
			},
		})
	}

	return findings
}

var wafSignatures = []struct {
	name    string
	headers map[string]string
	body    []string
}{
	{"Cloudflare", map[string]string{"Server": "cloudflare", "CF-RAY": ""}, []string{"cloudflare"}},
	{"AWS WAF", map[string]string{"X-Amzn-RequestId": ""}, []string{"awselb"}},
	{"Akamai", map[string]string{"X-Akamai-Transformed": ""}, []string{"akamai"}},
	{"Imperva", map[string]string{"X-CDN": "Imperva"}, []string{"imperva", "incapsula"}},
	{"Sucuri", map[string]string{"X-Sucuri-ID": ""}, []string{"sucuri"}},
	{"F5 BIG-IP", map[string]string{"Server": "BIG-IP", "X-WA-Info": ""}, nil},
	{"ModSecurity", map[string]string{"Server": "mod_security"}, []string{"modsecurity", "mod_security"}},
	{"Fortinet FortiWeb", map[string]string{"Server": "FortiWeb"}, nil},
	{"百度安全", map[string]string{}, []string{"bdstatic.com/security"}},
	{"阿里云WAF", map[string]string{"Server": "Tengine"}, []string{"errors.aliyun.com"}},
	{"腾讯云WAF", map[string]string{}, []string{"waf.tencent-cloud.com"}},
	{"长亭SafeLine", map[string]string{}, []string{"safeline"}},
}

func (m *FPEnhanceScanner) wafDetect(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	resp, body := m.sendRequest(ctx, baseURL)
	if resp == nil {
		return nil
	}

	xssURL := baseURL + "/?test=<script>alert(1)</script>"
	wafResp, wafBody := m.sendRequest(ctx, xssURL)

	var findings []*core.Finding

	checkResp := resp
	checkBody := body
	if wafResp != nil {
		checkResp = wafResp
		checkBody = wafBody
	}

	for _, sig := range wafSignatures {
		matched := false

		for header, expected := range sig.headers {
			val := checkResp.Header.Get(header)
			if val != "" {
				if expected == "" || strings.Contains(strings.ToLower(val), strings.ToLower(expected)) {
					matched = true
					break
				}
			}
		}

		if !matched {
			for _, pattern := range sig.body {
				if strings.Contains(strings.ToLower(checkBody), pattern) {
					matched = true
					break
				}
			}
		}

		if matched {
			findings = append(findings, &core.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "waf_detected",
				Title:       fmt.Sprintf("WAF检测: %s", sig.name),
				Description: fmt.Sprintf("目标使用 %s WAF/CDN 防护", sig.name),
				Severity:    "info",
				Confidence:  80,
				Timestamp:   time.Now(),
				Data: map[string]string{
					"waf_name": sig.name,
				},
			})
		}
	}

	if wafResp != nil && (wafResp.StatusCode == 403 || wafResp.StatusCode == 406 || wafResp.StatusCode == 503) && len(findings) == 0 {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "waf_detected",
			Title:       "检测到未知WAF",
			Description: fmt.Sprintf("XSS探针触发了 %d 响应，疑似存在WAF防护", wafResp.StatusCode),
			Severity:    "info",
			Confidence:  60,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"probe_status": fmt.Sprintf("%d", wafResp.StatusCode),
			},
		})
	}

	return findings
}

func (m *FPEnhanceScanner) jsFingerprint(ctx context.Context, target *core.Target, baseURL string) []*core.Finding {
	_, body := m.sendRequest(ctx, baseURL)
	if body == "" {
		return nil
	}

	jsLibs := []struct {
		pattern string
		name    string
	}{
		{"jquery", "jQuery"},
		{"react", "React"},
		{"vue", "Vue.js"},
		{"angular", "Angular"},
		{"bootstrap", "Bootstrap"},
		{"lodash", "Lodash"},
		{"moment", "Moment.js"},
		{"axios", "Axios"},
		{"webpack", "Webpack"},
		{"next", "Next.js"},
		{"nuxt", "Nuxt.js"},
		{"svelte", "Svelte"},
		{"tailwindcss", "Tailwind CSS"},
		{"elementui", "Element UI"},
		{"antd", "Ant Design"},
	}

	var detected []string
	lower := strings.ToLower(body)
	for _, lib := range jsLibs {
		if strings.Contains(lower, lib.pattern) {
			detected = append(detected, lib.name)
		}
	}

	if len(detected) > 0 {
		return []*core.Finding{{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "js_fingerprint",
			Title:       fmt.Sprintf("前端技术栈: %s", strings.Join(detected, ", ")),
			Description: fmt.Sprintf("检测到 %d 个前端框架/库", len(detected)),
			Severity:    "info",
			Confidence:  70,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"libraries": strings.Join(detected, ","),
				"count":     fmt.Sprintf("%d", len(detected)),
			},
		}}
	}

	return nil
}

func (m *FPEnhanceScanner) sendRequest(ctx context.Context, rawURL string) (*http.Response, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp, string(body)
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
