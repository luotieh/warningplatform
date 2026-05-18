package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CredentialsFile matches JSON from POST /cluster/scan-nodes/enroll (node-agent.credentials.json).
type CredentialsFile struct {
	Version   int    `json:"version"`
	MasterURL string `json:"master_url"`
	NodeUUID  string `json:"node_uuid"`
	Secret    string `json:"secret"`
	IssuedAt  string `json:"issued_at"`
	Label     string `json:"label,omitempty"`
	Topology  string `json:"topology,omitempty"`
}

// LoadCredentialsFile reads a credentials JSON file issued by the master.
func LoadCredentialsFile(path string) (*CredentialsFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f CredentialsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	f.MasterURL = strings.TrimSpace(f.MasterURL)
	f.NodeUUID = strings.TrimSpace(f.NodeUUID)
	f.Secret = strings.TrimSpace(f.Secret)
	if f.NodeUUID == "" || f.Secret == "" {
		return nil, fmt.Errorf("credentials file missing node_uuid or secret")
	}
	return &f, nil
}
