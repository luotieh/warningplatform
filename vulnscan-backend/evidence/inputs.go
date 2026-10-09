package evidence

import "time"

// Provenance describes externally parsed data, not an externally supplied verdict.
// Complete means complete within the explicitly supplied analysis window.
type Provenance struct {
	Verified  bool     `json:"verified"`
	Complete  bool     `json:"complete"`
	Version   string   `json:"version"`
	SourceIDs []string `json:"source_ids"`
}

type AnalysisWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type Baseline struct {
	Provenance
	FactID      FactID             `json:"fact_id"`
	Metrics     map[string]float64 `json:"metrics"`
	Frequencies map[string]float64 `json:"frequencies"`
}
type Input struct {
	Scope          Scope              `json:"scope"`
	Window         *AnalysisWindow    `json:"window"`
	Baselines      []Baseline         `json:"baselines"`
	DNS            *DNSData           `json:"dns"`
	HTTP           *HTTPData          `json:"http"`
	Network        *NetworkData       `json:"network"`
	TLS            *TLSData           `json:"tls"`
	History        *HistoryData       `json:"history"`
	Corroboration  *CorroborationData `json:"corroboration"`
	Authorizations *AuthorizationData `json:"authorizations"`
}
type DNSRecord struct {
	SourceID   string    `json:"source_id"`
	Time       time.Time `json:"time"`
	Domain     string    `json:"domain"`
	RCode      int       `json:"rcode"`
	RCodeKnown bool      `json:"r_code_known"`
	Answers    []string  `json:"answers"`
}
type DNSData struct {
	Provenance
	Records                []DNSRecord        `json:"records"`
	BigramLogProbabilities map[string]float64 `json:"bigram_log_probabilities"`
}
type HTTPRecord struct {
	SourceID                string                    `json:"source_id"`
	TransactionID           string                    `json:"transaction_id"`
	SessionID               string                    `json:"session_id"`
	Time                    time.Time                 `json:"time"`
	URL                     string                    `json:"url"`
	Method                  string                    `json:"method"`
	UserAgent               string                    `json:"user_agent"`
	Fields                  map[string]string         `json:"fields"`
	FieldValuesRedacted     bool                      `json:"field_values_redacted,omitempty"`
	EncodingSummary         *HTTPFieldEncodingSummary `json:"encoding_summary,omitempty"`
	BodyLength              *uint64                   `json:"body_length"`
	Truncated               bool                      `json:"truncated"`
	ResponseURL             string                    `json:"response_url"`
	ResponseStatus          int                       `json:"response_status"`
	ResponseLocation        string                    `json:"response_location"`
	ResponseVerified        bool                      `json:"response_verified"`
	FormAction              string                    `json:"form_action"`
	RedirectToTransactionID string                    `json:"redirect_to_transaction_id"`
	RedirectVerified        bool                      `json:"redirect_verified"`
	DeclaredBrand           string                    `json:"declared_brand"`
	BrandClaimVerified      bool                      `json:"brand_claim_verified"`
}
type Brand struct {
	Name              string   `json:"name"`
	AuthorizedDomains []string `json:"authorized_domains"`
}

type HTTPFieldEncodingSummary struct {
	Total   int `json:"total"`
	Encoded int `json:"encoded"`
	Longest int `json:"longest"`
}
type HTTPData struct {
	Provenance
	Records        []HTTPRecord `json:"records"`
	Brands         []Brand      `json:"brands"`
	BrandsVerified bool         `json:"brands_verified"`
}
type Connection struct {
	SourceID       string    `json:"source_id"`
	Time           time.Time `json:"time"`
	AssetID        string    `json:"asset_id"`
	Destination    string    `json:"destination"`
	Port           uint16    `json:"port"`
	AppProtocol    string    `json:"app_protocol"`
	ProtocolParsed bool      `json:"protocol_parsed"`
	PayloadBytes   *uint64   `json:"payload_bytes"`
	TCPState       string    `json:"tcp_state"`
	SessionID      string    `json:"session_id"`
}
type Session struct {
	SourceID       string    `json:"source_id"`
	ID             string    `json:"id"`
	Start          time.Time `json:"start"`
	End            time.Time `json:"end"`
	UpBytes        uint64    `json:"up_bytes"`
	DownBytes      uint64    `json:"down_bytes"`
	VolumeVerified bool      `json:"volume_verified"`
	HitIDs         []string  `json:"hit_ids"`
}
type Service struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
}
type NetworkData struct {
	Provenance
	Connections      []Connection `json:"connections"`
	Sessions         []Session    `json:"sessions"`
	Services         []Service    `json:"services"`
	ServicesVerified bool         `json:"services_verified"`
	ASN              string       `json:"asn"`
	Country          string       `json:"country"`
	Reputation       string       `json:"reputation"`
}
type TLSRecord struct {
	SourceID         string    `json:"source_id"`
	Time             time.Time `json:"time"`
	SNI              string    `json:"sni"`
	CertificateNames []string  `json:"certificate_names"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	ChainVerified    bool      `json:"chain_verified"`
	ChainValid       bool      `json:"chain_valid"`
	Issuer           string    `json:"issuer"`
	UserAgent        string    `json:"user_agent"`
	Fingerprint      string    `json:"fingerprint"`
	CertificatesDER  [][]byte  `json:"certificates_der"`
}
type TLSData struct {
	Provenance
	Records              []TLSRecord       `json:"records"`
	CDNExceptions        []string          `json:"cdn_exceptions"`
	ExceptionsVerified   bool              `json:"exceptions_verified"`
	TrustedIssuers       []string          `json:"trusted_issuers"`
	IssuersVerified      bool              `json:"issuers_verified"`
	FingerprintClients   map[string]string `json:"fingerprint_clients"`
	FingerprintsVerified bool              `json:"fingerprints_verified"`
	TrustRootsDER        [][]byte          `json:"trust_roots_der"`
}
type HistoryEvent struct {
	ID                 string             `json:"id"`
	AdjudicationID     string             `json:"adjudication_id"`
	Adjudication       string             `json:"adjudication"`
	Time               time.Time          `json:"time"`
	AssetID            string             `json:"asset_id"`
	IOC                string             `json:"ioc"`
	Family             string             `json:"family"`
	Endpoint           string             `json:"endpoint"`
	GroupID            string             `json:"group_id"`
	RuleFamily         string             `json:"rule_family"`
	Stage              string             `json:"stage"`
	Parameters         map[string]float64 `json:"parameters"`
	MemberIDs          []string           `json:"member_ids"`
	AdjudicationSource string             `json:"adjudication_source"`
	// Campaign and complete membership bindings are independently verified by
	// the trusted adapter; model labels and partial member lists are not proofs.
	CampaignID              string     `json:"campaign_id"`
	CampaignProvenance      Provenance `json:"campaign_provenance"`
	GroupMembershipVerified bool       `json:"group_membership_verified"`
}
type HistoryData struct {
	Provenance
	Events                    []HistoryEvent     `json:"events"`
	AsOf                      time.Time          `json:"as_of"`
	LookbackStart             time.Time          `json:"lookback_start"`
	IOC                       string             `json:"ioc"`
	Family                    string             `json:"family"`
	Endpoint                  string             `json:"endpoint"`
	CurrentStage              string             `json:"current_stage"`
	CurrentStageSource        string             `json:"current_stage_source"`
	CurrentStageProvenance    Provenance         `json:"current_stage_provenance"`
	CampaignID                string             `json:"campaign_id"`
	CampaignProvenance        Provenance         `json:"campaign_provenance"`
	CurrentParameters         map[string]float64 `json:"current_parameters"`
	GroupID                   string             `json:"group_id"`
	CurrentMemberIDs          []string           `json:"current_member_ids"`
	CurrentParametersVerified bool               `json:"current_parameters_verified"`
	GroupMembershipVerified   bool               `json:"group_membership_verified"`
}
type RuleRecord struct {
	ID                string `json:"id"`
	IndependenceGroup string `json:"independence_group"`
	OriginalSource    string `json:"original_source"`
}
type IntelRecord struct {
	ID             string `json:"id"`
	OriginalSource string `json:"original_source"`
	IOC            string `json:"ioc"`
	Type           string `json:"type"`
}
type CorroborationData struct {
	Provenance
	Rules              []RuleRecord       `json:"rules"`
	Intelligence       []IntelRecord      `json:"intelligence"`
	IOC                string             `json:"ioc"`
	IOCType            string             `json:"ioc_type"`
	HardTypeScores     map[string]float64 `json:"hard_type_scores"`
	HardScoresVerified bool               `json:"hard_scores_verified"`
}
type AuthorizationRecord struct {
	ID        string    `json:"id"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	AssetID   string    `json:"asset_id"`
	Endpoint  string    `json:"endpoint"`
	Domains   []string  `json:"domains"`
	Role      string    `json:"role"`
	TaskType  string    `json:"task_type"`
	Ports     []uint16  `json:"ports"`
	Protocols []string  `json:"protocols"`
	Targets   []string  `json:"targets"`
}
type AuthorizationData struct {
	Provenance
	Records []AuthorizationRecord `json:"records"`
}
type GroupMember struct {
	AssetID            string   `json:"asset_id"`
	Scope              Scope    `json:"scope"`
	HitIDs             []string `json:"hit_ids"`
	Subnet             string   `json:"subnet"`
	Role               string   `json:"role"`
	MembershipVerified bool     `json:"membership_verified"`
	Addresses          []string `json:"addresses"`
}
type GroupInput struct {
	Provenance
	ID          string         `json:"id"`
	Window      AnalysisWindow `json:"window"`
	Members     []GroupMember  `json:"members"`
	Baselines   []Baseline     `json:"baselines"`
	DNS         []DNSRecord    `json:"dns"`
	Connections []Connection   `json:"connections"`
	// DNSOwnership must map each DNS source to a verified member asset.
	DNSOwnership           map[string]string `json:"dns_ownership"`
	IOC                    string            `json:"ioc"`
	Endpoint               string            `json:"endpoint"`
	Family                 string            `json:"family"`
	History                *HistoryData      `json:"history"`
	DomainPatterns         []DomainPattern   `json:"domain_patterns"`
	DomainPatternsVerified bool              `json:"domain_patterns_verified"`
}

type DomainPattern struct {
	ID         string `json:"id"`
	Expression string `json:"expression"`
}
