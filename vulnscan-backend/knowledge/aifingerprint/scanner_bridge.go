package aifingerprint

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// ScannerBridge 将 AI 指纹能力桥接到扫描引擎。
// 当传统指纹规则库无法识别目标时，自动回退到 LLM 分析。
type ScannerBridge struct {
	svc      *EnhancedService
	enabled  bool
	cooldown time.Duration
	cache    map[string][]FingerprintResult
}

// NewScannerBridge 创建扫描引擎桥接。
func NewScannerBridge(svc *EnhancedService) *ScannerBridge {
	return &ScannerBridge{
		svc:      svc,
		enabled:  true,
		cooldown: 5 * time.Second,
		cache:    make(map[string][]FingerprintResult),
	}
}

// SetEnabled 启用/禁用 AI 指纹回退。
func (b *ScannerBridge) SetEnabled(enabled bool) {
	b.enabled = enabled
}

// IdentifyFromHTTP 从 HTTP 响应中提取指纹（当传统规则无匹配时调用）。
func (b *ScannerBridge) IdentifyFromHTTP(ctx context.Context, url string, resp *http.Response, body []byte) ([]FingerprintResult, error) {
	if !b.enabled || b.svc == nil {
		return nil, nil
	}

	cacheKey := url
	if cached, ok := b.cache[cacheKey]; ok {
		return cached, nil
	}

	rawData := make(map[string]string)

	if resp != nil {
		var headers strings.Builder
		for k, vals := range resp.Header {
			for _, v := range vals {
				headers.WriteString(fmt.Sprintf("%s: %s\n", k, v))
			}
		}
		rawData["http_headers"] = headers.String()
		rawData["status"] = resp.Status
	}

	if len(body) > 0 {
		htmlStr := string(body)
		if len(htmlStr) > 3000 {
			htmlStr = htmlStr[:3000]
		}
		rawData["html"] = htmlStr
	}

	if len(rawData) == 0 {
		return nil, nil
	}

	results, err := b.svc.AnalyzeFingerprintRAG(ctx, rawData)
	if err != nil {
		slog.Debug("[AIFingerprint] LLM fallback failed", "url", url, "error", err)
		return nil, err
	}

	b.cache[cacheKey] = results
	return results, nil
}

// IdentifyFromBanner 从服务 Banner 中提取指纹。
func (b *ScannerBridge) IdentifyFromBanner(ctx context.Context, host string, port int, banner string) ([]FingerprintResult, error) {
	if !b.enabled || b.svc == nil {
		return nil, nil
	}

	cacheKey := fmt.Sprintf("%s:%d", host, port)
	if cached, ok := b.cache[cacheKey]; ok {
		return cached, nil
	}

	rawData := map[string]string{
		"banner": banner,
		"target": fmt.Sprintf("%s:%d", host, port),
	}

	results, err := b.svc.AnalyzeFingerprintRAG(ctx, rawData)
	if err != nil {
		slog.Debug("[AIFingerprint] Banner LLM analysis failed", "host", host, "port", port, "error", err)
		return nil, err
	}

	b.cache[cacheKey] = results
	return results, nil
}

// IdentifyFromSSL 从 SSL/TLS 证书信息中提取组织指纹。
func (b *ScannerBridge) IdentifyFromSSL(ctx context.Context, host string, certInfo string) ([]FingerprintResult, error) {
	if !b.enabled || b.svc == nil {
		return nil, nil
	}

	rawData := map[string]string{
		"ssl_cert": certInfo,
		"target":   host,
	}

	return b.svc.AnalyzeFingerprintRAG(ctx, rawData)
}
