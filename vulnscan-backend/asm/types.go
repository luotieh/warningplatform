package asm

import "time"

type ASMProject struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Seeds       []Seed    `json:"seeds"`
	Schedule    string    `json:"schedule"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Seed struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type DiscoveredAsset struct {
	ID         string            `json:"id"`
	ProjectID  string            `json:"project_id"`
	Type       string            `json:"type"`
	Value      string            `json:"value"`
	Source     string            `json:"source"`
	FirstSeen  time.Time         `json:"first_seen"`
	LastSeen   time.Time         `json:"last_seen"`
	Attributes map[string]string `json:"attributes"`
	RiskScore  int               `json:"risk_score"`
	Status     string            `json:"status"`
}

type AssetChange struct {
	ID       string    `json:"id"`
	AssetID  string    `json:"asset_id"`
	Field    string    `json:"field"`
	OldValue string    `json:"old_value"`
	NewValue string    `json:"new_value"`
	ChangeAt time.Time `json:"change_at"`
	Severity string    `json:"severity"`
}

type AlertRule struct {
	ID        string            `json:"id"`
	ProjectID string            `json:"project_id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Condition map[string]string `json:"condition"`
	Actions   []AlertAction     `json:"actions"`
	Enabled   bool              `json:"enabled"`
}

type AlertAction struct {
	Type   string            `json:"type"`
	Config map[string]string `json:"config"`
}
