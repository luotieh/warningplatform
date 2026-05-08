package monitoragent

import (
	"context"
	"time"
)

type TaskMessage struct {
	ExecutionID string         `json:"execution_id"`
	TaskID      string         `json:"task_id"`
	Dimension   string         `json:"dimension"`
	URL         string         `json:"url"`
	Config      map[string]any `json:"config,omitempty"`
	Baseline    *BaselineMeta  `json:"baseline,omitempty"`
}

type BaselineMeta struct {
	Version           int            `json:"version"`
	Simhash           int64          `json:"simhash"`
	ContentHash       string         `json:"content_hash"`
	DomStructureHash  string         `json:"dom_structure_hash"`
	VisualHash        string         `json:"visual_hash"`
	Title             string         `json:"title"`
	StatusCode        int            `json:"status_code"`
	VisibleTextLength int            `json:"visible_text_length"`
	ExemptSelectors   []string       `json:"exempt_selectors"`
	ExternalResources map[string]any `json:"external_resources"`
	ObjKeyHTML        string         `json:"obj_key_html,omitempty"`
	ObjKeyText        string         `json:"obj_key_text,omitempty"`
	ObjKeyScreenshot  string         `json:"obj_key_screenshot,omitempty"`
}

type TaskResult struct {
	ExecutionID string `json:"execution_id"`
	TaskID      string `json:"task_id"`
	Dimension   string `json:"dimension"`
	URL         string `json:"url"`
	AgentID     string `json:"agent_id"`
	Status      string `json:"status"` // success / failed
	Result      string `json:"result"` // JSON
	Error       string `json:"error"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
}

type PageSnapshot struct {
	URL              string            `json:"url"`
	FinalURL         string            `json:"final_url"`
	StatusCode       int               `json:"status_code"`
	Headers          map[string]string `json:"headers"`
	RenderedHTML     string            `json:"rendered_html"`
	VisibleText      string            `json:"visible_text"`
	Screenshot       []byte            `json:"-"`
	Title            string            `json:"title"`
	ContentHash      string            `json:"content_hash"`
	DOMHash          string            `json:"dom_structure_hash"`
	VisualHash       string            `json:"visual_hash"`
	Links            []LinkInfo        `json:"links"`
	Scripts          []ScriptInfo      `json:"scripts"`
	ResolvedIPs      []string          `json:"resolved_ips"`
	DNSMS            float64           `json:"dns_ms"`
	TCPConnectMS     float64           `json:"tcp_connect_ms"`
	TLSHandshakeMS   float64           `json:"tls_handshake_ms"`
	TTFBMS           float64           `json:"ttfb_ms"`
	TotalMS          float64           `json:"total_ms"`
	SSLValid         bool              `json:"ssl_valid"`
	SSLIssuer        string            `json:"ssl_issuer"`
	SSLSubject       string            `json:"ssl_subject"`
	SSLExpiry        time.Time         `json:"ssl_expiry"`
	SSLNotBefore     time.Time         `json:"ssl_not_before"`
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

type LinkInfo struct {
	URL        string `json:"url"`
	IsExternal bool   `json:"is_external"`
	IsHidden   bool   `json:"is_hidden"`
}

type ScriptInfo struct {
	Src        string `json:"src"`
	IsExternal bool   `json:"is_external"`
	Snippet    string `json:"content_snippet"`
}

// Engine 检测引擎接口
type Engine interface {
	Name() string
	Run(ctx context.Context, task *TaskMessage, page *PageSnapshot) (map[string]any, error)
}

// RuleStore 规则数据访问
type RuleStore interface {
	GetModuleRules(moduleKey string) ([]byte, error)
	GetAllRules() (map[string][]byte, error)
}
