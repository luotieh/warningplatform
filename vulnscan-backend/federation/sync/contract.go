package sync

import (
	"encoding/json"
	"time"
)

type SyncItem struct {
	SyncVersion int64           `json:"sync_version"`
	Action      string          `json:"action"`    // "upsert" or "delete"
	DataType    string          `json:"data_type"` // "poc", "fingerprint", "rule"
	DataID      string          `json:"data_id"`
	Content     json.RawMessage `json:"content,omitempty"`
	Checksum    string          `json:"checksum,omitempty"`
}

type SyncResponse struct {
	Items         []SyncItem `json:"items"`
	LatestVersion int64      `json:"latest_version"`
	HasMore       bool       `json:"has_more"`
	ServerTime    time.Time  `json:"server_time"`
}

type SyncRequest struct {
	SinceVersion int64  `json:"since_version" form:"since_version"`
	Limit        int    `json:"limit" form:"limit"`
	DataType     string `json:"data_type" form:"data_type"`
}

type ManifestResponse struct {
	Versions   map[string]int64 `json:"versions"`
	ServerTime time.Time        `json:"server_time"`
}

type RegisterRequest struct {
	SubMasterCode string   `json:"sub_master_code"`
	Hostname      string   `json:"hostname"`
	IPAddress     string   `json:"ip_address"`
	Version       string   `json:"version"`
	LicenseKey    string   `json:"license_key"`
	Capabilities  []string `json:"capabilities"`
}

type RegisterResponse struct {
	APIToken        string           `json:"api_token"`
	SyncInterval    string           `json:"sync_interval"`
	ReportInterval  string           `json:"report_interval"`
	Quota           QuotaInfo        `json:"quota"`
	CurrentVersions map[string]int64 `json:"current_versions"`
}

type QuotaInfo struct {
	MaxWorkers  int      `json:"max_workers"`
	MaxTargets  int      `json:"max_targets"`
	MaxScansDay int      `json:"max_scans_day"`
	Modules     []string `json:"modules"`
	Features    []string `json:"features"`
}

type HeartbeatRequest struct {
	SubMasterCode  string  `json:"sub_master_code"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemPercent     float64 `json:"mem_percent"`
	WorkerCount    int     `json:"worker_count"`
	ActiveTasks    int     `json:"active_tasks"`
	CurrentTargets int     `json:"current_targets"`
	ScansToday     int     `json:"scans_today"`
	PocVersion     int64   `json:"poc_version"`
	FPVersion      int64   `json:"fingerprint_version"`
	RuleVersion    int64   `json:"rule_version"`
}

type HeartbeatResponse struct {
	Status          string           `json:"status"`
	Commands        []Command        `json:"commands,omitempty"`
	CurrentVersions map[string]int64 `json:"current_versions,omitempty"`
}

type Command struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}
