package model

const (
	FingerprintStatusActive   = "active"
	FingerprintStatusDisabled = "disabled"
	FingerprintStatusDraft    = "draft"

	ProbeTypePassive = "passive" // 被动等待 Banner
	ProbeTypeActive  = "active"  // 主动发送探测包

	MatchTypeRegex  = "regex"
	MatchTypeWord   = "word"
	MatchTypeHex    = "hex"
	MatchTypeHeader = "header" // HTTP Header 匹配
	MatchTypePath   = "path"   // HTTP Path 匹配
	MatchTypeTLS    = "tls"    // TLS 证书匹配
)

// ServiceFingerprint 服务指纹 — 数据库驱动的协议识别规则
type ServiceFingerprint struct {
	BaseModel
	Name        string `gorm:"type:varchar(128);not null;index" json:"name"`
	Service     string `gorm:"type:varchar(64);not null;index" json:"service"`
	Protocol    string `gorm:"type:varchar(16);default:'tcp'" json:"protocol"`
	ProbeType   string `gorm:"type:varchar(16);default:'passive'" json:"probe_type"`
	ProbeData   string `gorm:"type:text" json:"probe_data"`
	MatchType   string `gorm:"type:varchar(16);default:'regex'" json:"match_type"`
	MatchRule   string `gorm:"type:text;not null" json:"match_rule"`
	VersionExpr string `gorm:"type:text" json:"version_expr"`
	Priority    int    `gorm:"default:50" json:"priority"`
	Ports       string `gorm:"type:text" json:"ports"`
	Status      string `gorm:"type:varchar(16);default:'active'" json:"status"`
	Source      string `gorm:"type:varchar(64)" json:"source"`
	Description string `gorm:"type:text" json:"description"`
	SyncVersion int64  `gorm:"index;default:0" json:"sync_version"`
	SourceType  string `gorm:"type:varchar(20);default:'local'" json:"source_type"`

	// HTTP 深度识别相关字段
	HTTPPaths     string `gorm:"type:text" json:"http_paths"`                       // 多路径探测，逗号分隔
	HTTPHeaders   string `gorm:"type:text" json:"http_headers"`                     // 自定义请求头，JSON 格式
	HTTPMethod    string `gorm:"type:varchar(16);default:'GET'" json:"http_method"` // HTTP 方法
	HTTPMatchBody bool   `gorm:"default:false" json:"http_match_body"`              // 是否匹配响应体

	// TLS 证书分析相关字段
	TLSMatchCN       bool `gorm:"default:false" json:"tls_match_cn"`        // 是否匹配证书 CN
	TLSMatchSAN      bool `gorm:"default:false" json:"tls_match_san"`       // 是否匹配证书 SAN
	TLSMatchOrg      bool `gorm:"default:false" json:"tls_match_org"`       // 是否匹配证书组织
	TLSMatchIssuer   bool `gorm:"default:false" json:"tls_match_issuer"`    // 是否匹配证书颁发者
	TLSMatchExpiry   bool `gorm:"default:false" json:"tls_match_expiry"`    // 是否匹配证书过期时间
	TLSMatchSelfSign bool `gorm:"default:false" json:"tls_match_self_sign"` // 是否匹配自签名证书

	// 探测链相关字段
	ProbeChain     string `gorm:"type:text" json:"probe_chain"`             // 探测链配置，JSON 格式
	ProbeChainNext string `gorm:"type:varchar(64)" json:"probe_chain_next"` // 下一步探测的指纹 ID
}

func (ServiceFingerprint) TableName() string { return "vs_service_fingerprint" }

// PortServiceMap 端口-服务映射 — 替代硬编码的 wellKnownService
type PortServiceMap struct {
	BaseModel
	Port     int    `gorm:"not null;uniqueIndex:idx_port_proto" json:"port"`
	Protocol string `gorm:"type:varchar(16);default:'tcp';uniqueIndex:idx_port_proto" json:"protocol"`
	Service  string `gorm:"type:varchar(64);not null" json:"service"`
	Status   string `gorm:"type:varchar(16);default:'active'" json:"status"`
}

func (PortServiceMap) TableName() string { return "vs_port_service_map" }
