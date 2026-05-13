package intel

import "time"

type CVEEntry struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSSScore   float64   `json:"cvss_score"`
	CVSSVector  string    `json:"cvss_vector"`
	CWE         []string  `json:"cwe"`
	CPE         []string  `json:"cpe"`
	References  []string  `json:"references"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	HasExploit  bool      `json:"has_exploit"`
	InKEV       bool      `json:"in_kev"`
	// Exploit 增强字段
	ExploitType    string   `json:"exploit_type"`
	ExploitURLs    []string `json:"exploit_urls"`
	Difficulty     string   `json:"difficulty"`
	Impact         string   `json:"impact"`
	EPSSScore      float64  `json:"epss_score"`
	EPSSPercentile float64  `json:"epss_percentile"`
}

type CPEEntry struct {
	CPE23    string `json:"cpe23"`
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Version  string `json:"version"`
	Update   string `json:"update"`
	Edition  string `json:"edition"`
	Language string `json:"language"`
}

type FingerprintCPEMapping struct {
	Product    string   `json:"product"`
	Version    string   `json:"version"`
	CPEMatches []string `json:"cpe_matches"`
}

type VulnMatch struct {
	CVE        CVEEntry `json:"cve"`
	MatchedCPE string   `json:"matched_cpe"`
	MatchType  string   `json:"match_type"`
	Confidence int      `json:"confidence"`
}

type IntelSource struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	URL          string    `json:"url"`
	LastSync     time.Time `json:"last_sync"`
	EntryCount   int       `json:"entry_count"`
	Enabled      bool      `json:"enabled"`
	SyncInterval string    `json:"sync_interval"`
	APIKey       string    `json:"api_key,omitempty"`
	Custom       bool      `json:"custom"`
}

// --- Request types for parameter binding ---

// handler.go

type AddSourceReq struct {
	Name         string `json:"name" binding:"required"`
	Type         string `json:"type" binding:"required"`
	URL          string `json:"url" binding:"required"`
	SyncInterval string `json:"sync_interval"`
	APIKey       string `json:"api_key"`
	Enabled      bool   `json:"enabled"`
}

type UpdateSourceReq struct {
	URL          *string `json:"url"`
	SyncInterval *string `json:"sync_interval"`
	APIKey       *string `json:"api_key"`
	Enabled      *bool   `json:"enabled"`
}

type BatchAnalyzeReq struct {
	AssetIDs []string `json:"asset_ids"`
}

// ioc.go

type CreateIOCReq struct {
	Type        string   `json:"type" binding:"required"`
	Value       string   `json:"value" binding:"required"`
	ThreatType  string   `json:"threat_type"`
	Severity    string   `json:"severity"`
	Source      string   `json:"source"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	ExpiresAt   *string  `json:"expires_at"`
}

type BatchImportIOCReq struct {
	Items []BatchImportIOCItem `json:"items"`
}

type BatchImportIOCItem struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	ThreatType  string `json:"threat_type"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

type CheckIOCReq struct {
	Values []string `json:"values" binding:"required"`
}

// subscription.go

type CreateSubscriptionReq struct {
	Name        string   `json:"name" binding:"required"`
	Products    []string `json:"products"`
	Keywords    []string `json:"keywords"`
	Severities  []string `json:"severities"`
	OnlyExploit bool     `json:"only_exploit"`
	OnlyKEV     bool     `json:"only_kev"`
}

type UpdateSubscriptionReq struct {
	Name        *string  `json:"name"`
	Products    []string `json:"products"`
	Keywords    []string `json:"keywords"`
	Severities  []string `json:"severities"`
	OnlyExploit *bool    `json:"only_exploit"`
	OnlyKEV     *bool    `json:"only_kev"`
	Enabled     *bool    `json:"enabled"`
}

// cpe_mapping.go

type AddCPEMappingReq struct {
	Product    string   `json:"product" binding:"required"`
	Version    string   `json:"version"`
	CPEMatches []string `json:"cpe_matches" binding:"required"`
}

type UpdateCPEMappingReq struct {
	Version    *string  `json:"version"`
	CPEMatches []string `json:"cpe_matches"`
}
