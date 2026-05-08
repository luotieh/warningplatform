package model

const (
	FingerprintStatusActive   = "active"
	FingerprintStatusDisabled = "disabled"
	FingerprintStatusDraft    = "draft"

	ProbeTypePassive = "passive" // 被动等待 Banner
	ProbeTypeActive  = "active"  // 主动发送探测包
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
