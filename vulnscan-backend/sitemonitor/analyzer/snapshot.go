package analyzer

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

type snapshotData struct {
	URL              string            `json:"url"`
	FinalURL         string            `json:"final_url"`
	StatusCode       int               `json:"status_code"`
	Headers          map[string]string `json:"headers"`
	Title            string            `json:"title"`
	RenderedHTML     string            `json:"rendered_html"`
	VisibleText      string            `json:"visible_text"`
	ContentHash      string            `json:"content_hash"`
	Links            []linkInfo        `json:"links"`
	Scripts          []scriptInfo      `json:"scripts"`
	Iframes          []iframeInfo      `json:"iframes"`
	MetaRedirect     *metaRedirect     `json:"meta_redirect,omitempty"`
	JSRedirects      []jsRedirect      `json:"js_redirects,omitempty"`
	Cloaking         *cloakingData     `json:"cloaking,omitempty"`
	ResolvedIPs      []string          `json:"resolved_ips"`
	DNSMS            float64           `json:"dns_ms"`
	TCPConnectMS     float64           `json:"tcp_connect_ms"`
	TLSHandshakeMS   float64           `json:"tls_handshake_ms"`
	TTFBMS           float64           `json:"ttfb_ms"`
	TotalMS          float64           `json:"total_ms"`
	SSLValid         bool              `json:"ssl_valid"`
	SSLIssuer        string            `json:"ssl_issuer"`
	SSLSubject       string            `json:"ssl_subject"`
	SSLExpiry        string            `json:"ssl_expiry"`
	SSLNotBefore     string            `json:"ssl_not_before"`
	SSLDaysLeft      int               `json:"ssl_days_remaining"`
	SSLProtocol      string            `json:"ssl_protocol"`
	SSLCipher        string            `json:"ssl_cipher"`
	SSLChainComplete bool              `json:"ssl_chain_complete"`
	SSLChainDepth    int               `json:"ssl_chain_depth"`
	SSLSAN           []string          `json:"ssl_san"`
	SSLSerialNumber  string            `json:"ssl_serial_number"`
	SSLSignatureAlg  string            `json:"ssl_signature_alg"`
	SSLKeyBits       int               `json:"ssl_key_bits"`
	SSLErrors        []string          `json:"ssl_errors"`
	Error            string            `json:"error"`
}

type linkInfo struct {
	URL        string `json:"url"`
	IsExternal bool   `json:"is_external"`
	IsHidden   bool   `json:"is_hidden"`
}

type scriptInfo struct {
	Src        string `json:"src"`
	IsExternal bool   `json:"is_external"`
	Snippet    string `json:"content_snippet"`
}

type iframeInfo struct {
	Src        string `json:"src"`
	IsExternal bool   `json:"is_external"`
	IsHidden   bool   `json:"is_hidden"`
	Width      string `json:"width,omitempty"`
	Height     string `json:"height,omitempty"`
	Style      string `json:"style,omitempty"`
}

type metaRedirect struct {
	URL     string `json:"url"`
	Seconds int    `json:"seconds"`
}

type jsRedirect struct {
	Type    string `json:"type"`
	Target  string `json:"target"`
	Snippet string `json:"snippet"`
	Delay   int    `json:"delay,omitempty"`
}

type cloakingData struct {
	Detected   bool                `json:"detected"`
	NormalHash string              `json:"normal_hash"`
	BotResults []cloakingBotResult `json:"bot_results,omitempty"`
	Similarity float64             `json:"similarity,omitempty"`
}

type cloakingBotResult struct {
	BotName     string  `json:"bot_name"`
	ContentHash string  `json:"content_hash"`
	Similarity  float64 `json:"similarity"`
	TitleMatch  bool    `json:"title_match"`
	BotTitle    string  `json:"bot_title,omitempty"`
}

func parseSnapshot(raw string) (*snapshotData, error) {
	var s snapshotData
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}
	return &s, nil
}

func extractHost(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rawURL = rawURL[idx+3:]
	}
	if idx := strings.Index(rawURL, "/"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

// sameRootDomain 判断两个域名是否属于同一注册域名。
// 例如 bing.com / www.bing.com / cn.bing.com 都属于 bing.com。
// 对于国家码二级后缀（如 .com.cn, .co.uk, .net.cn 等），会比较最后三段。
func sameRootDomain(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == b {
		return true
	}
	return registeredDomain(a) == registeredDomain(b)
}

// twoPartTLDs 国家码二级后缀集合（如 .com.cn, .co.uk）
var twoPartTLDs = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.kr": true, "or.kr": true,
	"com.tw": true, "org.tw": true, "net.tw": true,
	"com.hk": true, "org.hk": true, "net.hk": true,
	"com.sg": true, "org.sg": true,
	"com.br": true, "org.br": true,
	"co.in": true, "org.in": true, "net.in": true,
	"com.ru": true, "org.ru": true,
	"co.nz": true, "org.nz": true,
	"com.mx": true, "org.mx": true,
}

func registeredDomain(host string) string {
	parts := strings.Split(host, ".")
	n := len(parts)
	if n <= 2 {
		return host
	}
	// 检查是否是二级 TLD（如 com.cn, co.uk）
	if n >= 3 {
		lastTwo := parts[n-2] + "." + parts[n-1]
		if twoPartTLDs[lastTwo] {
			return strings.Join(parts[n-3:], ".")
		}
	}
	return strings.Join(parts[n-2:], ".")
}

func absInt(x int) int {
	return int(math.Abs(float64(x)))
}
